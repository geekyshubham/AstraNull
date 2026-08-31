import { Fragment, useEffect, useState, type ComponentPropsWithoutRef, type CSSProperties, type FormEvent, type HTMLAttributes, type KeyboardEvent as ReactKeyboardEvent, type MouseEvent as ReactMouseEvent, type ReactNode } from 'react';
import {
  Activity,
  Bot,
  CheckCircle2,
  CircleHelp,
  CircleMinus,
  Cloud,
  CloudSun,
  ClipboardList,
  FileCheck2,
  FileText,
  Globe2,
  KeyRound,
  LifeBuoy,
  ListChecks,
  Network,
  PlugZap,
  RefreshCw,
  Route,
  Server,
  ServerCog,
  ShieldCheck,
  Siren,
  Target,
  TrendingDown,
  TrendingUp,
  TriangleAlert,
  UserCog
} from 'lucide-react';
import { ReadinessPostureDonut } from '../components/charts/readiness-posture-donut';
import { WafSummaryPanel } from '../components/dashboard/waf-summary-panel';
import { ScoreTrend } from '../components/charts/score-trend';
import { VectorHeatmap } from '../components/charts/vector-heatmap';
import { ResourceMatrix } from '../components/charts/resource-matrix';
import { Badge } from '../components/ui/badge';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../components/ui/card';
import {
  effectivePolicyTargetKind,
  isPolicyTargetCompatible,
  policySupportedTargetKinds,
  TargetGroupPicker,
} from '../components/policies/target-group-picker';
import { EmptyState } from '../components/ui/empty-state';
import { emptyStateFromApi, readMetaAction } from '../lib/empty-from-api';
import { ConfirmModal, FormModal, formatMutationSuccessMessage, renderFriendlyEmptyState } from '../lib/crud-ui';
import { apiErrorMessage, humanizeErrorCode } from '../lib/error-messages';
import { Progress, type ProgressTone } from '../components/ui/progress';
import { DataTable, type TableColumn } from '../components/ui/table';
import { Select, type SelectOption } from '../components/ui/select';
import { AnchorButton, Button } from '../components/ui/button';
import { Tabs } from '../components/ui/tabs';
import { buildApiHeaders, requestJson } from '../lib/api';
import { canAccessRoute } from '../lib/route-access';
import { resolveDashboardMetrics, resolveRecentRuns } from '../lib/dashboard-metrics';
import { buildEnvironmentReadinessRows } from '../lib/environments';
import { buildDetailHref } from '../lib/route-params';
import { DEFENSIVE_RULES, ROUTE_BY_ID } from '../lib/navigation';
import { routeTabs } from '../lib/prototype-manifest';
import type { DataItem, PortalConfig, PortalData, ReadinessFactor, RouteId, Session } from '../lib/types';
import { countLabel, formatAuditAction, formatDate, formatNumber, formatResourceTypeLabel, formatSeverityLabel, pluralize } from '../lib/utils';

function getString(item: DataItem, keys: string[], fallback = '—') {
  for (const key of keys) {
    const value = item[key];
    if (value !== undefined && value !== null && value !== '') return String(value);
  }
  return fallback;
}

function getNumber(item: DataItem, keys: string[], fallback = 0) {
  for (const key of keys) {
    const value = item[key];
    if (typeof value === 'number' && Number.isFinite(value)) return value;
  }
  return fallback;
}

function getNestedNumber(item: DataItem | null | undefined, path: string[], fallback = 0) {
  let current: unknown = item;
  for (const key of path) {
    if (!current || typeof current !== 'object' || Array.isArray(current)) return fallback;
    current = (current as DataItem)[key];
  }
  return typeof current === 'number' && Number.isFinite(current) ? current : fallback;
}

function getNestedItem(item: DataItem | null | undefined, path: string[]) {
  let current: unknown = item;
  for (const key of path) {
    if (!current || typeof current !== 'object' || Array.isArray(current)) return null;
    current = (current as DataItem)[key];
  }
  return current && typeof current === 'object' && !Array.isArray(current) ? current as DataItem : null;
}

function getNestedArray(item: DataItem | null | undefined, path: string[]) {
  let current: unknown = item;
  for (const key of path) {
    if (!current || typeof current !== 'object' || Array.isArray(current)) return [];
    current = (current as DataItem)[key];
  }
  return Array.isArray(current) ? current as DataItem[] : [];
}

function getNestedString(item: DataItem | null | undefined, path: string[], fallback = '—') {
  let current: unknown = item;
  for (const key of path) {
    if (!current || typeof current !== 'object' || Array.isArray(current)) return fallback;
    current = (current as DataItem)[key];
  }
  if (current !== undefined && current !== null && current !== '') return String(current);
  return fallback;
}

function getHashQueryParam(key: string) {
  if (typeof window === 'undefined') return '';
  const hash = window.location.hash.replace(/^#/, '');
  const queryInHash = hash.includes('?') ? hash.slice(hash.indexOf('?') + 1) : '';
  const params = new URLSearchParams(queryInHash || window.location.search);
  return params.get(key) ?? '';
}

type UiBadgeTone = 'default' | 'success' | 'warn' | 'danger' | 'info' | 'muted';

function scoreProgressTone(score: number): ProgressTone {
  if (score >= 80) return 'success';
  if (score >= 55) return 'warn';
  return 'danger';
}

const TARGET_KIND_SELECT_OPTIONS: SelectOption[] = [
  { value: 'fqdn', label: 'FQDN' },
  { value: 'url', label: 'URL' },
  { value: 'ip_port', label: 'IP/Port' },
  { value: 'dns', label: 'DNS service' },
  { value: 'canary', label: 'Canary endpoint' }
];

const POLICY_CADENCE_OPTIONS: SelectOption[] = [
  { value: 'manual', label: 'Manual' },
  { value: 'daily', label: 'Daily' },
  { value: 'weekly', label: 'Weekly' },
  { value: 'monthly', label: 'Monthly' }
];

const POLICY_VERDICT_OPTIONS: SelectOption[] = [
  { value: 'pass', label: 'Pass' },
  { value: 'warn', label: 'Warn' },
  { value: 'fail', label: 'Fail' },
  { value: 'manual_review', label: 'Manual review' }
];

type PolicyTargetBinding = {
  targets: DataItem[];
  selectedTargetId: string;
  loading: boolean;
  error: string;
};

const BOOTSTRAP_EXPIRY_OPTIONS: SelectOption[] = [
  { value: '15m', label: '15 minutes' },
  { value: '1h', label: '1 hour' },
  { value: '24h', label: '24 hours' }
];

function formatPolicyStateLabel(state: string) {
  if (state === 'paused') return 'Paused';
  if (state === 'active') return 'Active';
  return state.replace(/_/g, ' ');
}

function formatPolicyCadenceLabel(cadence: string) {
  return POLICY_CADENCE_OPTIONS.find((option) => option.value === cadence)?.label ?? cadence.replace(/_/g, ' ');
}

function formatPolicyVerdictLabel(verdict: string) {
  return POLICY_VERDICT_OPTIONS.find((option) => option.value === verdict)?.label ?? verdict.replace(/_/g, ' ');
}

/** A schedule is SOC-scheduled when its bound check is soc_gated / high-scale, or it carries an explicit gate flag. */
function isPolicySocGated(policy: DataItem, checksById: Map<string, DataItem>): boolean {
  const embeddedCheck = policy.check && typeof policy.check === 'object' ? (policy.check as DataItem) : {};
  const checkId = getString(policy, ['check_id'], getString(embeddedCheck, ['check_id'], ''));
  const catalogCheck = (checkId ? checksById.get(checkId) : undefined) ?? {};
  const safetyClass = getString(embeddedCheck, ['safety_class'], getString(catalogCheck, ['safety_class'], ''));
  const riskClass = getString(embeddedCheck, ['risk_class'], getString(catalogCheck, ['risk_class'], ''));
  const vectorFamily = getString(embeddedCheck, ['vector_family'], getString(catalogCheck, ['vector_family'], ''));
  if (safetyClass === 'soc_gated' || riskClass === 'soc_gated' || riskClass === 'prohibited') return true;
  if (vectorFamily === 'high_scale') return true;
  if (policy.high_scale === true || policy.soc_gated === true) return true;
  const explicitGate = getString(policy, ['gated', 'soc_scheduled'], '').toLowerCase();
  return explicitGate === 'true' || explicitGate === 'high_scale';
}

const POLICY_CADENCE_INTERVAL_MS: Record<string, number> = {
  daily: 86_400_000,
  weekly: 604_800_000,
  monthly: 2_592_000_000
};

/** Derive a schedule's next run from real fields: explicit next_run_at, else cadence projected from the last known anchor. */
function derivePolicyNextRun(policy: DataItem, socGated: boolean): { label: string; iso: string | null } {
  if (socGated) return { label: 'Awaiting SOC', iso: null };
  const explicit = getString(policy, ['next_run_at', 'next_run', 'scheduled_at'], '');
  if (explicit) {
    const ts = Date.parse(explicit);
    return Number.isFinite(ts)
      ? { label: formatDate(explicit), iso: new Date(ts).toISOString() }
      : { label: explicit, iso: null };
  }
  const cadence = getString(policy, ['cadence'], 'manual');
  if (cadence === 'manual') return { label: 'On demand', iso: null };
  const interval = POLICY_CADENCE_INTERVAL_MS[cadence];
  if (!interval) return { label: '—', iso: null };
  const anchor = Date.parse(getString(policy, ['last_run_at', 'updated_at', 'created_at'], ''));
  if (!Number.isFinite(anchor)) return { label: '—', iso: null };
  let next = anchor + interval;
  const now = Date.now();
  while (next < now) next += interval;
  const iso = new Date(next).toISOString();
  return { label: formatDate(iso), iso };
}

function formatRunStatusLabel(status: string) {
  const labels: Record<string, string> = {
    planned: 'Planned',
    running: 'Running',
    collecting: 'Collecting',
    completed: 'Completed',
    verdicted: 'Verdicted',
    cancelled: 'Cancelled',
    failed: 'Failed'
  };
  return labels[status] ?? status.replace(/_/g, ' ');
}

function runStatusBadgeTone(status: string): UiBadgeTone {
  if (status === 'verdicted' || status === 'completed') return 'success';
  if (status === 'running' || status === 'collecting') return 'info';
  if (status === 'cancelled' || status === 'failed') return 'danger';
  if (status === 'planned') return 'muted';
  return 'warn';
}

function findingSeverityBadgeTone(severity: string): UiBadgeTone {
  const normalized = severity.toLowerCase();
  if (normalized === 'critical' || normalized === 'high' || normalized === 's1' || normalized === 's2') return 'danger';
  if (normalized === 'medium' || normalized === 's3') return 'warn';
  if (normalized === 'low' || normalized === 's4') return 'info';
  return 'muted';
}

function highScaleStateBadgeTone(state: string): UiBadgeTone {
  if (['submitted', 'under_review'].includes(state)) return 'warn';
  if (['approved', 'scheduled', 'completed', 'executed'].includes(state)) return 'success';
  if (['rejected', 'cancelled', 'stopped'].includes(state)) return 'danger';
  return 'info';
}

function lifecycleBadgeTone(state: string): UiBadgeTone {
  if (state === 'active') return 'success';
  if (state === 'suspended') return 'danger';
  return 'warn';
}

function subscriptionStatusBadgeTone(status: string): UiBadgeTone {
  if (status === 'active') return 'success';
  if (status === 'past_due' || status === 'suspended') return 'warn';
  if (status === 'cancelled') return 'muted';
  return 'info';
}

function DashboardWorkspaceSkeleton() {
  return (
    <div className="dashboard-grid" aria-busy="true" aria-live="polite">
      <Card className="score-card" density="compact">
        <CardContent className="stack-tight">
          <div className="skeleton skeleton-text" />
          <div className="skeleton" />
        </CardContent>
      </Card>
      <div className="metric-grid">
        {Array.from({ length: 4 }, (_, index) => (
          <Card key={index} className="metric-card" density="compact">
            <div className="skeleton skeleton-text" />
            <div className="skeleton skeleton-text" />
          </Card>
        ))}
      </div>
    </div>
  );
}

const SUPPORT_CONTACT_MAILTO = 'mailto:support@astranull.example?subject=AstraNull%20support%20request';

function featureEnabled(data: PortalData, key: 'waf_posture' | 'external_discovery' | 'connectors') {
  return Boolean(data.deploymentFeatures?.[key]);
}

/** Keep native table-row semantics while adding click and keyboard navigation. */
function detailRowProps(
  route: RouteId,
  id: string,
  label: string
): Omit<HTMLAttributes<HTMLTableRowElement>, 'key'> {
  const href = buildDetailHref(route, id);
  const navigate = () => {
    // buildDetailHref returns `${pathname}${search}#route?id=...`; assigning that whole string to
    // location.hash would nest it inside the fragment (e.g. `#/app#route?id=`). Navigate with the
    // bare `route?id=...` fragment so the hash router resolves the detail route correctly.
    const hashIndex = href.indexOf('#');
    window.location.hash = hashIndex >= 0 ? href.slice(hashIndex + 1) : href;
  };
  return {
    tabIndex: 0,
    style: { cursor: 'pointer' },
    'aria-label': label,
    onClick: (event: ReactMouseEvent<HTMLTableRowElement>) => {
      const target = event.target as HTMLElement;
      if (target.closest('a, button')) return;
      navigate();
    },
    onKeyDown: (event: ReactKeyboardEvent<HTMLTableRowElement>) => {
      if (event.key !== 'Enter' && event.key !== ' ') return;
      event.preventDefault();
      navigate();
    }
  };
}

export function PageHeader({
  route,
  eyebrow,
  title,
  description,
  variant = 'default',
  actions
}: {
  route: RouteId;
  eyebrow?: string;
  title?: ReactNode;
  description?: ReactNode;
  variant?: 'default' | 'detail';
  actions?: ReactNode;
}) {
  const item = ROUTE_BY_ID.get(route);
  if (variant === 'detail') {
    return (
      <div className="page-head page-head-detail">
        {eyebrow ? <p className="eyebrow">{eyebrow}</p> : null}
      </div>
    );
  }
  return (
    <div className="page-head">
      <div>
        <p className="eyebrow">{eyebrow ?? item?.group}</p>
        <h1>{title ?? item?.label}</h1>
        <p>{description ?? item?.description}</p>
      </div>
      {actions ? <div className="row-actions">{actions}</div> : null}
    </div>
  );
}

export function MetricCard({
  label,
  value,
  sub,
  icon: Icon,
  tone = 'default',
  showStatusBadge
}: {
  label: string;
  value: string | number;
  sub: string;
  icon: typeof Activity;
  tone?: 'default' | 'success' | 'warn' | 'danger' | 'info' | 'muted';
  /** When true, shows a corner status badge. Defaults to on for non-default tones. */
  showStatusBadge?: boolean;
}) {
  const cornerBadge = showStatusBadge ?? (tone === 'warn' || tone === 'danger');
  return (
    <Card className={cornerBadge ? 'metric-card' : 'metric-card plain-metric'}>
      <div className="metric-icon" aria-hidden>
        <Icon size={18} aria-hidden />
      </div>
      <div>
        <span>{label}</span>
        <strong>{value}</strong>
        <p>{sub}</p>
      </div>
      {cornerBadge ? (
        <Badge tone={tone}>{tone === 'warn' ? 'attention' : 'critical'}</Badge>
      ) : null}
    </Card>
  );
}

/** One-line operational summary — use instead of hero metric grids on governed pages. */
export function PageContextSummary({ children }: { children: ReactNode }) {
  return <p className="page-context-summary">{children}</p>;
}

type LucideIcon = typeof Activity;

function KpiCell({
  label,
  value,
  delta,
  deltaVariant
}: {
  label: string;
  value: ReactNode;
  delta: ReactNode;
  deltaVariant?: 'up' | 'down';
}) {
  const deltaClassName = deltaVariant ? `kpi-delta ${deltaVariant}` : 'kpi-delta';
  // Carry the up/down trend through a colored Lucide glyph (graphical, needs only 3:1) and keep the
  // delta label on an AA-safe token. The bare --success text token is ~3.3:1 on the light theme's
  // white KPI surface (DESIGN.md flags it "large only"), which fails WCAG AA 4.5:1 at this 11px
  // size; the glyph preserves the direction signal without small colored text on white.
  const DeltaIcon = deltaVariant === 'up' ? TrendingUp : deltaVariant === 'down' ? TrendingDown : null;
  return (
    <div className="kpi-cell">
      <div className="kpi-label">{label}</div>
      <div className="kpi-value">{value}</div>
      {DeltaIcon ? (
        <div className={deltaClassName} style={{ display: 'inline-flex', alignItems: 'center', gap: 'var(--space-1)' }}>
          <DeltaIcon size={12} aria-hidden />
          <span style={{ color: 'var(--fg-2)', minWidth: 0, overflowWrap: 'anywhere' }}>{delta}</span>
        </div>
      ) : (
        <div className={deltaClassName}>{delta}</div>
      )}
    </div>
  );
}

function PanelCardHeader({
  title,
  description,
  trailing
}: {
  title: ReactNode;
  description?: ReactNode;
  trailing?: ReactNode;
}) {
  const headings = (
    <>
      <CardTitle>{title}</CardTitle>
      {description ? <CardDescription>{description}</CardDescription> : null}
    </>
  );
  if (!trailing) {
    return <CardHeader>{headings}</CardHeader>;
  }
  return (
    <CardHeader>
      <div>{headings}</div>
      {trailing}
    </CardHeader>
  );
}

function SettingsNote({ icon: Icon, children }: { icon: LucideIcon; children: ReactNode }) {
  return (
    <div>
      <Icon size={18} aria-hidden />
      <span>{children}</span>
    </div>
  );
}

function CalloutNote({
  icon: Icon,
  tone,
  children
}: {
  icon: LucideIcon;
  tone?: 'info' | 'warn';
  children: ReactNode;
}) {
  return (
    <div className={tone ? `callout ${tone}` : 'callout'}>
      <Icon size={18} aria-hidden />
      <span>{children}</span>
    </div>
  );
}

function FormNumberField({
  label,
  name,
  hint,
  type = 'number',
  ...inputProps
}: {
  label: string;
  name: string;
  hint: string;
} & ComponentPropsWithoutRef<'input'>) {
  return (
    <label>
      <span>{label}</span>
      <input name={name} type={type} {...inputProps} />
      <span className="muted">{hint}</span>
    </label>
  );
}

export function DefensiveRulesPanel() {
  return (
    <Card>
      <CardHeader>
        <CardTitle>Product guardrails</CardTitle>
        <CardDescription>Every workflow in this UI keeps the defensive validation rules visible.</CardDescription>
      </CardHeader>
      <CardContent className="rule-grid">
        {DEFENSIVE_RULES.map((rule) => (
          <div className="rule" key={rule.title}>
            <CheckCircle2 size={17} aria-hidden />
            <div>
              <strong>{rule.title}</strong>
              <p>{rule.body}</p>
            </div>
          </div>
        ))}
      </CardContent>
    </Card>
  );
}

type DashboardTabId = 'overview' | 'risk-trends';

const DASHBOARD_TAB_STORAGE_KEY = 'astranull-dashboard-tab';
const DASHBOARD_TAB_IDS: readonly DashboardTabId[] = ['overview', 'risk-trends'];

function readDashboardTabId(): DashboardTabId {
  const fromHash = getHashQueryParam('tab');
  if (DASHBOARD_TAB_IDS.includes(fromHash as DashboardTabId)) return fromHash as DashboardTabId;
  if (typeof window !== 'undefined') {
    const stored = window.sessionStorage.getItem(DASHBOARD_TAB_STORAGE_KEY);
    if (stored && DASHBOARD_TAB_IDS.includes(stored as DashboardTabId)) return stored as DashboardTabId;
  }
  return 'overview';
}

function persistDashboardTab(tab: DashboardTabId) {
  if (typeof window === 'undefined') return;
  window.sessionStorage.setItem(DASHBOARD_TAB_STORAGE_KEY, tab);
  const base = `${window.location.pathname}${window.location.search}#dashboard`;
  window.history.replaceState(null, '', `${base}?tab=${encodeURIComponent(tab)}`);
}

function agentsForTargetGroup(data: PortalData, groupId: string) {
  return data.agents.filter((agent) => getString(agent, ['target_group_id']) === groupId);
}

function businessServiceRows(data: PortalData) {
  return data.targetGroups
    .filter((group) => group.archived_at == null)
    .map((group) => {
      const groupId = getString(group, ['id'], '');
      const boundAgents = agentsForTargetGroup(data, groupId);
      const onlineAgents = boundAgents.filter((agent) => getString(agent, ['status']) === 'online').length;
      const openFindings = data.findings.filter((finding) =>
        getString(finding, ['target_group_id']) === groupId &&
        getString(finding, ['status'], 'open') === 'open'
      ).length;
      const completedRuns = data.runs.filter((run) =>
        getString(run, ['target_group_id']) === groupId &&
        ['completed', 'verdicted'].includes(getString(run, ['status']))
      ).length;
      return {
        group,
        groupId,
        boundAgents: boundAgents.length,
        onlineAgents,
        openFindings,
        completedRuns
      };
    });
}

function evidenceFeedRows(data: PortalData, limit = 10) {
  const custodyAudit = data.audit
    .filter((entry) => {
      const action = getString(entry, ['action', 'event_type']).toLowerCase();
      return action.includes('evidence') || action.includes('custody') || action.includes('export');
    })
    .map((entry) => ({
      id: getString(entry, ['id'], ''),
      kind: getString(entry, ['action', 'event_type'], 'audit'),
      created_at: entry.created_at ?? entry.timestamp,
      source: 'audit'
    }));

  const evidenceRows = [...data.evidence]
    .map((item) => ({
      id: getString(item, ['id'], ''),
      kind: getString(item, ['kind', 'type'], 'evidence'),
      created_at: item.created_at,
      source: 'evidence'
    }));

  return [...evidenceRows, ...custodyAudit]
    .sort((left, right) => String(right.created_at ?? '').localeCompare(String(left.created_at ?? '')))
    .slice(0, limit);
}

function targetGroupDisplayName(data: PortalData, groupId: string) {
  const group = data.targetGroups.find((item) => getString(item, ['id'], '') === groupId);
  return getString(group ?? {}, ['name', 'title'], groupId || '—');
}

function checkDisplayName(data: PortalData, checkId: string) {
  const check = data.checks.find((item) => getString(item, ['check_id'], '') === checkId);
  return getString(check ?? {}, ['name', 'title'], checkId || '—');
}

function runDisplayLabel(data: PortalData, run: DataItem) {
  const titled = getString(run, ['name', 'title'], '');
  if (titled) return titled;
  const checkName = checkDisplayName(data, getString(run, ['check_id']));
  const groupName = targetGroupDisplayName(data, getString(run, ['target_group_id']));
  return `${checkName} · ${groupName}`;
}

function evidenceDisplayLabel(item: DataItem) {
  return getString(item, ['title', 'label'], '') || getString(item, ['kind', 'type'], 'Evidence record');
}

function highScaleRequestLabel(data: PortalData, request: DataItem) {
  const objective = getString(request, ['objective', 'reason'], '').trim();
  if (objective) return objective;
  return targetGroupDisplayName(data, getString(request, ['target_group_id']));
}

type DashboardNextStep = { key: string; title: string; detail: string; href: string; tone: 'warn' | 'info' | 'success' };

function buildDashboardNextSteps(data: PortalData, metrics: ReturnType<typeof resolveDashboardMetrics>): DashboardNextStep[] {
  const steps: DashboardNextStep[] = [];
  const activeGroups = data.targetGroups.filter((group) => group.archived_at == null);
  if (activeGroups.length === 0) {
    steps.push({
      key: 'declare-scope',
      title: 'Declare your first target group',
      detail: 'Add the business services you want to validate before any checks can run.',
      href: '#target-groups',
      tone: 'info'
    });
  }
  if (metrics.agentsOnline === 0 && data.agents.length === 0) {
    steps.push({
      key: 'install-agent',
      title: 'Optionally add an observation agent',
      detail: 'External validation works without an agent. Add one only when you want correlated internal or origin evidence.',
      href: '#agents',
      tone: 'info'
    });
  }
  if (metrics.openFindings > 0) {
    const topFinding = data.findings.find((finding) => getString(finding, ['status'], 'open') === 'open');
    const findingId = getString(topFinding ?? {}, ['id'], '');
    steps.push({
      key: 'triage-findings',
      title: `Triage ${metrics.openFindings} open finding${metrics.openFindings === 1 ? '' : 's'}`,
      detail: topFinding ? getString(topFinding, ['title'], 'Review evidence-backed gaps.') : 'Review evidence-backed gaps.',
      href: findingId ? buildDetailHref('finding-detail', findingId) : '#findings',
      tone: 'warn'
    });
  }
  if (!data.runs.some((run) => ['completed', 'verdicted'].includes(getString(run, ['status'])))) {
    steps.push({
      key: 'first-run',
      title: 'Run validation',
      detail: 'Complete at least one check to populate readiness evidence.',
      href: '#runs',
      tone: 'info'
    });
  }
  if (data.highScale.some((request) => ['submitted', 'under_review'].includes(getString(request, ['state'])))) {
    steps.push({
      key: 'high-scale-pack',
      title: 'Finish high-scale authorization metadata',
      detail: 'SOC review stays blocked until required authorization artifacts are uploaded.',
      href: '#runs',
      tone: 'warn'
    });
  }
  return steps.slice(0, 5);
}

function declaredEnvironmentComplete(data: PortalData) {
  const fromGroups = new Set(
    data.targetGroups
      .filter((group) => group.archived_at == null)
      .map((group) => getString(group, ['environment_id'], '').trim())
      .filter(Boolean)
  );
  if (fromGroups.size > 0) return true;
  return data.bootstrapTokens.some((token) => getString(token, ['environment_id'], '').trim() !== '');
}

function declaredTargetGroupComplete(data: PortalData) {
  return data.targetGroups.some((group) => group.archived_at == null);
}

const DASHBOARD_EVIDENCE_RUN_STATUSES = new Set(['completed', 'verdicted']);

function formatDashboardShortRelative(iso: string) {
  const ts = Date.parse(iso);
  if (!Number.isFinite(ts)) return '—';
  const seconds = Math.round(Math.max(0, Date.now() - ts) / 1000);
  if (seconds < 60) return `${seconds}s`;
  const minutes = Math.round(seconds / 60);
  if (minutes < 120) return `${minutes}m`;
  const hours = Math.round(minutes / 60);
  if (hours < 48) return `${hours}h`;
  const days = Math.round(hours / 24);
  return `${days}d`;
}

const READINESS_SCALE_POINTS = 100;

/**
 * Weighted readiness factors from GET /v1/state `readiness.factors[]` (docs/ux/14 §4.1).
 * Factor scores are points on the 100-point readiness scale, so a factor's bar is its share
 * of that scale. Nothing here is keyed off a hardcoded factor list: labels, scores, and
 * details all come from the payload.
 */
export function ReadinessFactorsPanel({ factors }: { factors: ReadinessFactor[] }) {
  const rows = factors.filter((factor) => typeof factor?.score === 'number' && Number.isFinite(factor.score));

  if (rows.length === 0) {
    return (
      <EmptyState
        icon={Activity}
        title="Weighted factors unavailable."
        body="Factor scores appear once the platform publishes an evidence-backed readiness score."
      />
    );
  }

  return (
    <div className="gauge-legend" data-testid="readiness-factors">
      {rows.map((factor, index) => {
        const key = getString(factor as DataItem, ['key'], '');
        const label = getString(factor as DataItem, ['label', 'key'], 'Factor');
        const score = Number(factor.score);
        const scale =
          typeof factor.weight === 'number' && Number.isFinite(factor.weight) && factor.weight > 0
            ? factor.weight
            : READINESS_SCALE_POINTS;
        const share = Math.min(100, Math.max(0, (score / scale) * 100));
        const detail = getString(factor as DataItem, ['detail', 'reason'], '');
        const provenance = `Factor ${key || label}: ${score} of ${scale} points, from GET /v1/state readiness.factors`;

        return (
          <div className="stack-tight" key={key || `${label}-${index}`} data-testid="readiness-factor-row">
            <div className="legend-row">
              <span className="ld" style={{ background: 'var(--success)' }} aria-hidden="true" />
              <span className="lg-label" title={provenance}>{label}</span>
              <span
                className="lg-bar-wrap"
                role="img"
                aria-label={`${label} scored ${score} of ${scale} points`}
                title={provenance}
              >
                <span className="lg-bar" style={{ width: `${share}%`, background: 'var(--success)' }} />
              </span>
              <span className="lg-pct" title={provenance}>{score}</span>
              <b title={provenance}>{`/${scale}`}</b>
            </div>
            {detail ? (
              <p className="muted small" title="Factor detail from GET /v1/state readiness.factors[].detail">{detail}</p>
            ) : null}
          </div>
        );
      })}
    </div>
  );
}

type CorrelationStatus = 'pass' | 'review' | 'gap' | 'none';
type CorrelationCellData = { status: CorrelationStatus; pass: number; review: number; gap: number; total: number };

/** Vector families mirror components/charts/vector-heatmap.tsx so both matrices classify consistently. */
const CORRELATION_FAMILIES: { label: string; keys: string[] }[] = [
  { label: 'Origin', keys: ['origin'] },
  { label: 'L3/L4', keys: ['l3_l4', 'l3/l4', 'layer_3_4'] },
  { label: 'DNS', keys: ['dns'] },
  { label: 'L7/API', keys: ['l7_api', 'l7/api', 'application', 'api'] },
  { label: 'Protocol', keys: ['protocol', 'tls', 'http2', 'http3'] }
];

const CORRELATION_TONE_CLASS: Record<CorrelationStatus, string> = {
  pass: 'heatmap-cell heatmap-success',
  review: 'heatmap-cell heatmap-warn',
  gap: 'heatmap-cell heatmap-danger',
  none: 'heatmap-cell heatmap-muted'
};

const CORRELATION_LABEL: Record<CorrelationStatus, string> = {
  pass: 'Pass',
  review: 'Review',
  gap: 'Gap',
  none: 'No data'
};

function checkMatchesCorrelationFamily(check: DataItem, keys: string[]) {
  const haystack = [
    getString(check, ['vector_family'], ''),
    getString(check, ['category'], ''),
    getString(check, ['name'], ''),
    getString(check, ['check_id', 'id'], '')
  ].join(' ').toLowerCase();
  return keys.some((key) => haystack.includes(key));
}

function classifyCorrelationVerdict(verdict: string): CorrelationStatus | null {
  const key = verdict.trim().toLowerCase();
  if (!key || ['pending', 'planned', 'running'].includes(key)) return null;
  if (['pass', 'passed', 'protected', 'success', 'ok'].includes(key)) return 'pass';
  if (['gap', 'fail', 'failed', 'penetrated', 'bypassable', 'unprotected'].includes(key)) return 'gap';
  return 'review';
}

function extractRunVerdictString(run: DataItem): string {
  const raw = run.verdict;
  if (typeof raw === 'string') return raw;
  if (raw && typeof raw === 'object' && !Array.isArray(raw)) {
    return getString(raw as DataItem, ['verdict', 'status', 'result'], '');
  }
  return getString(run, ['verdict'], '');
}

/** Aggregate completed/verdicted runs for a target group + vector family into a pass/review/gap cell (worst-case wins). */
function buildCorrelationCell(runs: DataItem[], groupId: string, familyCheckIds: Set<string>): CorrelationCellData {
  if (!groupId || familyCheckIds.size === 0) return { status: 'none', pass: 0, review: 0, gap: 0, total: 0 };
  let pass = 0;
  let review = 0;
  let gap = 0;
  for (const run of runs) {
    if (getString(run, ['target_group_id'], '') !== groupId) continue;
    if (!familyCheckIds.has(getString(run, ['check_id'], ''))) continue;
    if (!['completed', 'verdicted'].includes(getString(run, ['status'], ''))) continue;
    const bucket = classifyCorrelationVerdict(extractRunVerdictString(run));
    if (bucket === 'pass') pass += 1;
    else if (bucket === 'review') review += 1;
    else if (bucket === 'gap') gap += 1;
  }
  const total = pass + review + gap;
  let status: CorrelationStatus = 'none';
  if (gap > 0) status = 'gap';
  else if (review > 0) status = 'review';
  else if (pass > 0) status = 'pass';
  return { status, pass, review, gap, total };
}

/** 16px inline SVG glyph (currentColor): tick for pass, dot for review, cross for gap, dash for no data. No Unicode glyphs. */
function CorrelationGlyph({ status }: { status: CorrelationStatus }) {
  if (status === 'pass') {
    return (
      <svg width="16" height="16" viewBox="0 0 16 16" aria-hidden="true" focusable="false">
        <path d="M3.5 8.5 L6.75 11.75 L12.5 4.5" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
      </svg>
    );
  }
  if (status === 'gap') {
    return (
      <svg width="16" height="16" viewBox="0 0 16 16" aria-hidden="true" focusable="false">
        <path d="M4.5 4.5 L11.5 11.5 M11.5 4.5 L4.5 11.5" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
      </svg>
    );
  }
  if (status === 'review') {
    return (
      <svg width="16" height="16" viewBox="0 0 16 16" aria-hidden="true" focusable="false">
        <circle cx="8" cy="8" r="3" fill="currentColor" />
      </svg>
    );
  }
  return (
    <svg width="16" height="16" viewBox="0 0 16 16" aria-hidden="true" focusable="false">
      <path d="M4.5 8 L11.5 8" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" opacity="0.55" />
    </svg>
  );
}

function CorrelationMatrixCell({ cell, familyLabel }: { cell: CorrelationCellData; familyLabel: string }) {
  const title = cell.status === 'none'
    ? `No correlated verdict for ${familyLabel} on this target group yet.`
    : `${CORRELATION_LABEL[cell.status]} · ${cell.pass} pass · ${cell.review} review · ${cell.gap} gap across ${cell.total} correlated run${cell.total === 1 ? '' : 's'}`;
  return (
    <span
      className={CORRELATION_TONE_CLASS[cell.status]}
      role="img"
      aria-label={`${familyLabel}: ${CORRELATION_LABEL[cell.status]}`}
      title={title}
    >
      <CorrelationGlyph status={cell.status} />
    </span>
  );
}

function CorrelationLegendItem({ status, label }: { status: CorrelationStatus; label: string }) {
  return (
    <span style={{ display: 'inline-flex', alignItems: 'center', gap: 'var(--space-1)' }}>
      <CorrelationGlyph status={status} /> {label}
    </span>
  );
}

/** Overview correlation matrix (§4.1.3): vector family x declared target group, pass/review/gap cells with inline SVG ticks. */
function DashboardCorrelationMatrix({
  checks,
  targetGroups,
  runs
}: {
  checks: DataItem[];
  targetGroups: DataItem[];
  runs: DataItem[];
}) {
  const groups = targetGroups.filter((group) => group.archived_at == null).slice(0, 5);
  if (groups.length === 0) {
    return (
      <EmptyState
        icon={Network}
        title="No declared target groups yet."
        body="Declare target groups before the correlation matrix can map vector families to verdicts."
        actionHref="#target-groups"
        actionLabel="Open target groups"
      />
    );
  }
  const families = CORRELATION_FAMILIES.map((family) => ({
    label: family.label,
    ids: new Set(
      checks
        .filter((check) => checkMatchesCorrelationFamily(check, family.keys))
        .map((check) => getString(check, ['check_id', 'id'], ''))
        .filter(Boolean)
    )
  }));
  const gridStyle = { '--heatmap-cols': CORRELATION_FAMILIES.length } as CSSProperties;
  return (
    <div className="heatmap">
      <div className="heatmap-grid heatmap-grid--variable" style={gridStyle}>
        <span className="heatmap-head">Target group</span>
        {families.map((family) => (
          <span className="heatmap-head" key={family.label}>{family.label}</span>
        ))}
        {groups.map((group, groupIndex) => {
          const groupId = getString(group, ['id'], '');
          return (
            <Fragment key={groupId || groupIndex}>
              <strong className="heatmap-name">{getString(group, ['name', 'id'], 'Declared group')}</strong>
              {families.map((family) => (
                <CorrelationMatrixCell
                  key={`${groupIndex}-${family.label}`}
                  cell={buildCorrelationCell(runs, groupId, family.ids)}
                  familyLabel={family.label}
                />
              ))}
            </Fragment>
          );
        })}
      </div>
      <div className="heatmap-legend">
        <CorrelationLegendItem status="pass" label="Pass" />
        <CorrelationLegendItem status="review" label="Review" />
        <CorrelationLegendItem status="gap" label="Gap" />
        <CorrelationLegendItem status="none" label="No data" />
      </div>
    </div>
  );
}

export function DashboardPage({
  data,
  config,
  session,
  onRefresh
}: {
  data: PortalData;
  config: PortalConfig;
  session: Session;
  onRefresh: () => Promise<void>;
}) {
  const [tab, setTab] = useState<DashboardTabId>(readDashboardTabId);
  const tabOptions = routeTabs('dashboard').map((item) => ({ id: item.id as DashboardTabId, label: item.label }));
  const workspaceHydrating = !data.state && data.targetGroups.length === 0 && data.runs.length === 0;

  useEffect(() => {
    const onHashChange = () => {
      const next = readDashboardTabId();
      setTab((current) => (current === next ? current : next));
    };
    window.addEventListener('hashchange', onHashChange);
    return () => window.removeEventListener('hashchange', onHashChange);
  }, []);

  function handleDashboardTabChange(next: DashboardTabId) {
    setTab(next);
    persistDashboardTab(next);
  }
  const score = typeof data.state?.readiness?.score === 'number' ? data.state.readiness.score : null;
  const metrics = resolveDashboardMetrics(data);
  const recentRuns = resolveRecentRuns(data, 6);
  const openFindingRows = data.findings
    .filter((finding) => getString(finding, ['status'], 'open') === 'open')
    .slice(0, 6);
  const agingFindings = [...data.findings]
    .filter((finding) => getString(finding, ['status'], 'open') === 'open')
    .sort((left, right) => String(left.created_at ?? left.id ?? '').localeCompare(String(right.created_at ?? right.id ?? '')))
    .slice(0, 8);
  const topTargetGroups = [...data.targetGroups]
    .sort((left, right) => String(right.criticality ?? right.business_criticality ?? '').localeCompare(String(left.criticality ?? left.business_criticality ?? '')))
    .slice(0, 4);
  const topAgents = [...data.agents].slice(0, 4);
  const agentsOnline = metrics.agentsOnline;
  const agentsTotal = data.agents.length;
  const agentsTotalDisplay = typeof data.state?.agents_total === 'number' ? data.state.agents_total : agentsTotal;
  const readinessDelta = typeof data.state?.readiness?.delta === 'number' ? data.state.readiness.delta : null;
  const activeTargetGroups = data.targetGroups.filter((group) => group.archived_at == null);
  const groupsWithEvidence = activeTargetGroups.filter((group) => {
    const groupId = getString(group, ['id'], '');
    return data.runs.some(
      (run) =>
        getString(run, ['target_group_id'], '') === groupId &&
        DASHBOARD_EVIDENCE_RUN_STATUSES.has(getString(run, ['status'], ''))
    );
  }).length;
  const coveragePercent = activeTargetGroups.length ? Math.round((groupsWithEvidence / activeTargetGroups.length) * 100) : 0;
  const openFindingsAtS2 = data.findings.filter(
    (finding) =>
      getString(finding, ['status'], 'open') === 'open' &&
      ['s2', 'high'].includes(getString(finding, ['severity'], '').toLowerCase())
  ).length;
  const lastRun = recentRuns[0] ?? null;
  const lastRunTimestamp = lastRun ? String(lastRun.created_at ?? lastRun.started_at ?? '') : '';
  const lastSafeRunValue = lastRunTimestamp ? formatDashboardShortRelative(lastRunTimestamp) : '—';
  const lastRunCheckCount = lastRun ? getNumber(lastRun, ['check_count'], 0) : 0;
  const tenantId =
    getString(data.tenant ?? {}, ['id', 'tenant_id'], '') || (data.state?.tenant_id ?? '');
  const tenantEyebrow = tenantId && tenantId !== '—' ? `Tenant · ${tenantId.toUpperCase()}` : 'Tenant';
  const killSwitch = data.state?.kill_switch ?? null;
  const killSwitchArmed = killSwitch?.active === true;
  const killSwitchReason = getString((killSwitch ?? {}) as DataItem, ['reason'], '');
  const killSwitchUpdatedAt = getString((killSwitch ?? {}) as DataItem, ['updated_at'], '');
  const readinessFactors = Array.isArray(data.state?.readiness?.factors) ? data.state.readiness.factors : [];

  function dashboardGroupVerdict(groupId: string): { label: string; tone: UiBadgeTone } {
    const latest = [...data.runs]
      .filter((run) => getString(run, ['target_group_id']) === groupId)
      .filter((run) => ['completed', 'verdicted'].includes(getString(run, ['status'])))
      .sort((left, right) =>
        String(right.started_at ?? right.created_at ?? '').localeCompare(
          String(left.started_at ?? left.created_at ?? '')
        )
      )[0];
    let verdict = '';
    if (latest) {
      const raw = latest.verdict;
      verdict =
        typeof raw === 'string'
          ? raw
          : raw && typeof raw === 'object' && !Array.isArray(raw)
            ? getString(raw as DataItem, ['verdict', 'status', 'result'], '')
            : getString(latest, ['verdict'], '');
    }
    const key = verdict.trim().toLowerCase();
    if (['pass', 'passed', 'ok', 'success', 'protected'].includes(key)) return { label: 'Pass', tone: 'success' };
    if (['gap', 'fail', 'failed', 'penetrated', 'bypassable', 'unprotected'].includes(key)) return { label: 'Gap', tone: 'danger' };
    if (['review', 'warn', 'partial', 'inconclusive', 'manual_review'].includes(key)) return { label: 'Review', tone: 'warn' };
    return { label: 'None', tone: 'muted' };
  }

  const dashboardGroupColumns: TableColumn<DataItem>[] = [
    { key: 'group', label: 'Group', render: (item) => <span className="mono">{getString(item, ['id'], '—')}</span> },
    { key: 'name', label: 'Name', render: (item) => getString(item, ['name', 'id'], '—') },
    {
      key: 'verdict',
      label: 'Verdict',
      render: (item) => {
        const verdict = dashboardGroupVerdict(getString(item, ['id'], ''));
        return <Badge tone={verdict.tone}>{verdict.label}</Badge>;
      }
    }
  ];

  const dashboardAgentColumns: TableColumn<DataItem>[] = [
    { key: 'agent', label: 'Agent', render: (item) => <span className="mono">{getString(item, ['id', 'hostname', 'name'], '—')}</span> },
    {
      key: 'heartbeat',
      label: 'Heartbeat',
      render: (item) => {
        const stamp = item.last_heartbeat_at ?? item.updated_at;
        return <span className="muted">{stamp ? formatDashboardShortRelative(String(stamp)) : '—'}</span>;
      }
    },
    {
      key: 'status',
      label: 'Status',
      render: (item) => {
        const status = getString(item, ['status'], 'unknown');
        return (
          <Badge tone={status === 'online' ? 'success' : 'warn'} title={`Agent status ${status} from agents API`}>
            {status}
          </Badge>
        );
      }
    }
  ];

  // Correlated check count = sum of posture segment counts (pass + review + gap),
  // mirroring ReadinessPostureDonut's resolver. Never the catalog size (data.checks.length).
  const readinessPosture = data.state?.readiness?.posture;
  const correlatedFromPosture =
    readinessPosture && typeof readinessPosture === 'object'
      ? Number(readinessPosture.pass ?? 0) + Number(readinessPosture.review ?? 0) + Number(readinessPosture.gap ?? 0)
      : 0;
  const correlatedCheckIds = new Set<string>();
  for (const run of data.runs) {
    const checkId = getString(run, ['check_id'], '');
    if (!checkId || !['completed', 'verdicted'].includes(getString(run, ['status'], ''))) continue;
    const rawVerdict = run.verdict;
    const verdictValue =
      typeof rawVerdict === 'string'
        ? rawVerdict
        : rawVerdict && typeof rawVerdict === 'object' && !Array.isArray(rawVerdict)
          ? getString(rawVerdict as DataItem, ['verdict', 'status', 'result'], '')
          : '';
    const verdictKey = verdictValue.trim().toLowerCase();
    if (!verdictKey || ['pending', 'planned', 'running'].includes(verdictKey)) continue;
    correlatedCheckIds.add(checkId);
  }
  const correlatedChecks = correlatedFromPosture > 0 ? correlatedFromPosture : correlatedCheckIds.size;

  function dashboardRunVerdict(run: DataItem): { label: string; tone: UiBadgeTone } {
    const raw = run.verdict;
    const verdict =
      typeof raw === 'string'
        ? raw
        : raw && typeof raw === 'object' && !Array.isArray(raw)
          ? getString(raw as DataItem, ['verdict', 'status', 'result'], '')
          : getString(run, ['verdict'], '');
    const key = verdict.trim().toLowerCase();
    if (['pass', 'passed', 'ok', 'success', 'protected'].includes(key)) return { label: 'Pass', tone: 'success' };
    if (['gap', 'fail', 'failed', 'penetrated', 'bypassable', 'unprotected'].includes(key)) return { label: 'Gap', tone: 'danger' };
    if (['review', 'warn', 'partial', 'inconclusive', 'manual_review'].includes(key)) return { label: 'Review', tone: 'warn' };
    const status = getString(run, ['status'], '');
    if (status) return { label: formatRunStatusLabel(status), tone: runStatusBadgeTone(status) };
    return { label: 'None', tone: 'muted' };
  }

  const dashboardFindingColumns: TableColumn<DataItem>[] = [
    { key: 'finding', label: 'Finding', render: (item) => <span className="mono">{getString(item, ['id'], '—')}</span> },
    {
      key: 'severity',
      label: 'Severity',
      render: (item) => (
        <Badge tone={findingSeverityBadgeTone(getString(item, ['severity']))}>{formatSeverityLabel(getString(item, ['severity'], 'unknown'))}</Badge>
      )
    },
    { key: 'owner', label: 'Owner', render: (item) => <span className="muted">{getString(item, ['assignee', 'owner'], 'unassigned')}</span> }
  ];

  const dashboardRunColumns: TableColumn<DataItem>[] = [
    { key: 'run', label: 'Run', render: (item) => <span className="mono">{getString(item, ['id'], '—')}</span> },
    {
      key: 'verdict',
      label: 'Verdict',
      render: (item) => {
        const verdict = dashboardRunVerdict(item);
        return <Badge tone={verdict.tone}>{verdict.label}</Badge>;
      }
    },
    { key: 'when', label: 'When', render: (item) => <span className="muted">{formatDate(item.created_at ?? item.started_at)}</span> }
  ];

  const dashboardEnvironmentRows = buildEnvironmentReadinessRows({
    targetGroups: data.targetGroups,
    runs: data.runs,
    findings: data.findings
  }).slice(0, 5);

  const dashboardEnvironmentColumns: TableColumn<(typeof dashboardEnvironmentRows)[number]>[] = [
    { key: 'environment', label: 'Environment', render: (row) => <span className="mono">{row.id}</span> },
    { key: 'groups', label: 'Target groups', render: (row) => <span className="tabular-nums">{row.groupCount}</span> },
    {
      key: 'status',
      label: 'Status',
      render: (row) => {
        const tone: UiBadgeTone = row.state === 'covered' ? 'success' : row.state === 'partial evidence' ? 'warn' : 'muted';
        const label = row.state === 'covered' ? 'Validated' : row.state === 'partial evidence' ? 'Review' : 'Needs evidence';
        return <Badge tone={tone}>{label}</Badge>;
      }
    }
  ];

  return (
    <div className="content">
      <PageHeader
        route="dashboard"
        eyebrow={tenantEyebrow}
        title="Readiness overview"
        description="Every verdict below traces to observed probe data, agent observations, or explicit declarations."
      />
      <Tabs value={tab} options={tabOptions} onChange={handleDashboardTabChange} className="tabs-wrap" />
      {tab === 'overview' ? (
        workspaceHydrating ? (
          <DashboardWorkspaceSkeleton />
        ) : (
        <>
          {killSwitchArmed ? (
            <div className="form-banner error stack-tight" role="alert">
              <strong>SOC kill switch is armed</strong>
              {killSwitchReason ? (
                <span title="Kill switch reason from GET /v1/state kill_switch.reason">{killSwitchReason}</span>
              ) : null}
              {killSwitchUpdatedAt ? (
                <span title="Kill switch updated_at from GET /v1/state kill_switch.updated_at">
                  Armed {formatDate(killSwitchUpdatedAt)}
                </span>
              ) : null}
            </div>
          ) : null}
          <div className="kpi-row">
            <KpiCell
              label="Readiness"
              value={
                <>
                  {score ?? '—'}
                  {score !== null ? <span className="unit">/100</span> : null}
                </>
              }
              delta={readinessDelta !== null ? `${readinessDelta > 0 ? '+' : ''}${readinessDelta} vs last cycle` : '—'}
              deltaVariant={
                readinessDelta !== null && readinessDelta !== 0
                  ? readinessDelta > 0
                    ? 'up'
                    : 'down'
                  : undefined
              }
            />
            <KpiCell
              label="Coverage"
              value={
                <>
                  {coveragePercent}
                  <span className="unit">%</span>
                </>
              }
              delta={`${formatNumber(metrics.targetGroups)} ${pluralize(metrics.targetGroups, 'target')}`}
            />
            <KpiCell label="Open findings" value={metrics.openFindings} delta={`${openFindingsAtS2} at Severity 2 (High)`} />
            <KpiCell
              label="Agents healthy"
              value={`${agentsOnline}/${agentsTotalDisplay || agentsOnline}`}
              delta="all heartbeats ≤ 30s"
            />
            <KpiCell
              label="Last run"
              value={lastSafeRunValue}
              delta={lastRun ? `${getString(lastRun, ['id'], '—')} · ${lastRunCheckCount} checks` : 'No runs yet'}
            />
          </div>

          <div className="dash-grid dash-grid--masonry">
            <Card>
              <CardHeader>
                <CardTitle>Readiness posture</CardTitle>
                <CardDescription>{countLabel(correlatedChecks, 'check')} correlated · this cycle</CardDescription>
              </CardHeader>
              <CardContent>
                <ReadinessPostureDonut state={data.state} runs={data.runs} checks={data.checks} />
              </CardContent>
            </Card>
            <Card>
              <CardHeader>
                <CardTitle>Open findings</CardTitle>
                <AnchorButton variant="ghost" size="sm" href="#findings">Triage</AnchorButton>
              </CardHeader>
              <CardContent>
                <DataTable
                  columns={dashboardFindingColumns}
                  items={openFindingRows}
                  getRowId={(item) => getString(item, ['id'], '')}
                  getRowProps={(item) => {
                    const id = getString(item, ['id'], '');
                    return id ? detailRowProps('finding-detail', id, `Open finding ${id} detail`) : {};
                  }}
                  empty={<EmptyState icon={TriangleAlert} title="No open findings." body="Findings appear after validation runs produce evidence-backed gaps." actionHref="#findings" actionLabel="Open findings" />}
                />
              </CardContent>
            </Card>
            <Card>
              <CardHeader>
                <div>
                  <CardTitle>Recent runs</CardTitle>
                  <CardDescription>Recent validation activity</CardDescription>
                </div>
                <AnchorButton variant="ghost" size="sm" href="#runs">All runs</AnchorButton>
              </CardHeader>
              <CardContent>
                <DataTable
                  columns={dashboardRunColumns}
                  items={recentRuns}
                  getRowId={(item) => getString(item, ['id'], '')}
                  getRowProps={(item) => {
                    const id = getString(item, ['id'], '');
                    return id ? detailRowProps('run-detail', id, `Open run ${id} detail`) : {};
                  }}
                  empty={<EmptyState icon={ListChecks} title="No test runs yet." body="Start a validation run from Test Runs after declaring scope." actionHref="#runs" actionLabel="Open test runs" />}
                />
              </CardContent>
            </Card>
            <Card>
              <CardHeader>
                <div>
                  <CardTitle>Target group status</CardTitle>
                  <CardDescription>declared scope</CardDescription>
                </div>
                <AnchorButton variant="ghost" size="sm" href="#target-groups">All target groups</AnchorButton>
              </CardHeader>
              <CardContent>
                <DataTable
                  columns={dashboardGroupColumns}
                  items={topTargetGroups}
                  getRowId={(item) => getString(item, ['id'], '')}
                  getRowProps={(item) => {
                    const id = getString(item, ['id'], '');
                    return id ? detailRowProps('target-group-detail', id, `Open target group ${id} detail`) : {};
                  }}
                  empty={<EmptyState icon={Target} title="No target groups yet." body="Declare target groups to map business services to validation scope." actionHref="#target-groups" actionLabel="Open target groups" />}
                />
              </CardContent>
            </Card>
            <Card>
              <CardHeader>
                <CardTitle>Agent health</CardTitle>
                <CardDescription>outbound-only</CardDescription>
              </CardHeader>
              <CardContent>
                <DataTable
                  columns={dashboardAgentColumns}
                  items={topAgents}
                  getRowId={(item) => getString(item, ['id'], '')}
                  getRowProps={(item) => {
                    const id = getString(item, ['id'], '');
                    return id ? detailRowProps('agent-detail', id, `Open agent ${id} detail`) : {};
                  }}
                  empty={<EmptyState icon={Bot} title="No agents registered." body="External checks remain available. Add an outbound agent only to enrich results with internal or origin observations." actionHref="#agents" actionLabel="Explore optional agents" />}
                />
              </CardContent>
            </Card>
            <Card>
              <CardHeader>
                <div>
                  <CardTitle>Environment status</CardTitle>
                  <CardDescription>declared scope</CardDescription>
                </div>
                <AnchorButton variant="ghost" size="sm" href="#environments">All environments</AnchorButton>
              </CardHeader>
              <CardContent>
                <DataTable
                  columns={dashboardEnvironmentColumns}
                  items={dashboardEnvironmentRows}
                  getRowId={(row) => row.id}
                  getRowProps={(row) => (row.id ? detailRowProps('environment-detail', row.id, `Open environment ${row.id} detail`) : {})}
                  empty={<EmptyState icon={ServerCog} title="No environments yet." body="Create a declared target group with an environment ID to populate this view." actionHref="#target-groups" actionLabel="Open target groups" />}
                />
              </CardContent>
            </Card>
          </div>
          <Card>
            <CardHeader>
              <CardTitle>WAF summary</CardTitle>
              <CardDescription>Rolled up across declared target groups. Per-target detail on the target page.</CardDescription>
            </CardHeader>
            <CardContent>
              <WafSummaryPanel summary={data.wafCoverageSummary} />
            </CardContent>
          </Card>
          <Card>
            <CardHeader>
              <CardTitle>Weighted factors</CardTitle>
              <CardDescription>Each factor contributes its points to the published readiness score.</CardDescription>
            </CardHeader>
            <CardContent>
              <ReadinessFactorsPanel factors={readinessFactors} />
            </CardContent>
          </Card>
        </>
        )
      ) : null}
      {tab === 'risk-trends' ? (
        <div className="risk-trends-stack">
          <div className="risk-trends-grid">
          <Card>
            <CardHeader>
              <CardTitle>Readiness trend</CardTitle>
              <CardDescription>Score trajectory derived from validation run history.</CardDescription>
            </CardHeader>
            <CardContent>
              {score === null ? (
                <EmptyState icon={Activity} title="Readiness score unavailable." body="Trend appears after the platform publishes an evidence-backed score." />
              ) : (
                <ScoreTrend runs={data.runs} currentScore={score} />
              )}
            </CardContent>
          </Card>
          <Card>
            <CardHeader>
              <CardTitle>Aging open findings</CardTitle>
              <CardDescription>Oldest open gaps that still pressure readiness.</CardDescription>
            </CardHeader>
            <CardContent>
              {agingFindings.length === 0 ? (
                <EmptyState icon={TriangleAlert} title="No open findings." body="Open findings appear after validation runs produce evidence-backed gaps." actionLabel="Open findings" actionHref="#findings" />
              ) : (
                <ul className="dashboard-link-list">
                  {agingFindings.map((finding) => {
                    const id = getString(finding, ['id'], '');
                    const title = getString(finding, ['title', 'summary'], id);
                    return (
                      <li key={id}>
                        <div className="dashboard-link-copy">
                          <strong>{title}</strong>
                          <span className="dashboard-link-meta">
                            <Badge tone={findingSeverityBadgeTone(getString(finding, ['severity']))}>{formatSeverityLabel(getString(finding, ['severity'], 'unknown'))}</Badge>
                            <span className="muted">opened {formatDate(finding.created_at)}</span>
                          </span>
                        </div>
                        <AnchorButton size="sm" variant="secondary" href={id ? buildDetailHref('finding-detail', id) : '#findings'}>Triage</AnchorButton>
                      </li>
                    );
                  })}
                </ul>
              )}
            </CardContent>
          </Card>
          </div>
          <Card>
            <CardHeader>
              <CardTitle>Vector coverage matrix</CardTitle>
              <CardDescription>Coverage by vector family and declared target group.</CardDescription>
            </CardHeader>
            <CardContent>
              <VectorHeatmap
                checks={data.checks}
                targetGroups={data.targetGroups}
                testPolicies={data.testPolicies}
                runs={data.runs}
                evidence={data.evidence}
              />
            </CardContent>
          </Card>
          <Card>
            <CardHeader>
              <CardTitle>Resource exhaustion matrix</CardTitle>
              <CardDescription>
                Stored verdict posture by exhausted resource, target applicability, and 30-day evidence freshness.
              </CardDescription>
            </CardHeader>
            <CardContent>
              <ResourceMatrix
                checks={data.checks}
                targetGroups={data.targetGroups}
                runs={data.runs}
                evidence={data.evidence}
                config={config}
                session={session}
                dataLoadError={[
                  data.loadErrors.checks,
                  data.loadErrors.targetGroups,
                  data.loadErrors.runs,
                  data.loadErrors.evidence
                ].filter(Boolean).join(' ') || null}
                onRefresh={onRefresh}
              />
            </CardContent>
          </Card>
        </div>
      ) : null}

    </div>
  );
}

export function TargetGroupsPage({
  data,
  config,
  session,
  onRefresh
}: {
  data: PortalData;
  config: PortalConfig;
  session: Session;
  onRefresh: () => Promise<void>;
}) {
  const [addTargetGroupId, setAddTargetGroupId] = useState(() => getString(data.targetGroups[0] ?? {}, ['id'], ''));
  const [addTargetKind, setAddTargetKind] = useState('fqdn');
  const [environmentFilter, setEnvironmentFilter] = useState(() => getHashQueryParam('environment_id'));
  const [showCreateMoreOptions, setShowCreateMoreOptions] = useState(false);
  const [busy, setBusy] = useState('');
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');
  const [tenantEnvironments, setTenantEnvironments] = useState<DataItem[]>([]);
  const [selectedEnvironmentId, setSelectedEnvironmentId] = useState('');
  const filteredGroups = environmentFilter
    ? data.targetGroups.filter((group) => getString(group, ['environment_id'], '') === environmentFilter)
    : data.targetGroups;
  const addTargetGroup = data.targetGroups.find((group) => getString(group, ['id'], '') === addTargetGroupId) ?? data.targetGroups[0] ?? null;
  const effectiveGroupId = getString(addTargetGroup ?? {}, ['id'], addTargetGroupId);

  useEffect(() => {
    const onHashChange = () => setEnvironmentFilter(getHashQueryParam('environment_id'));
    window.addEventListener('hashchange', onHashChange);
    return () => window.removeEventListener('hashchange', onHashChange);
  }, []);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const response = await requestJson(config, session, '/v1/environments') as { items?: DataItem[] } | DataItem[];
        const items = Array.isArray(response)
          ? response
          : Array.isArray(response?.items) ? response.items : [];
        if (!cancelled) setTenantEnvironments(items);
      } catch {
        if (!cancelled) setTenantEnvironments([]);
      }
    })();
    return () => { cancelled = true; };
  }, [config, session]);

  const environmentSelectOptions: SelectOption[] = tenantEnvironments
    .map((env) => ({
      value: getString(env, ['id'], ''),
      label: getString(env, ['name'], getString(env, ['id'], '')) || getString(env, ['id'], '')
    }))
    .filter((option) => option.value);

  useEffect(() => {
    if (environmentSelectOptions.length === 0) return;
    if (!selectedEnvironmentId || !environmentSelectOptions.some((option) => option.value === selectedEnvironmentId)) {
      setSelectedEnvironmentId(environmentSelectOptions[0].value);
    }
  }, [environmentSelectOptions, selectedEnvironmentId]);

  useEffect(() => {
    const firstId = getString(filteredGroups[0] ?? data.targetGroups[0] ?? {}, ['id'], '');
    if (!addTargetGroupId && firstId) setAddTargetGroupId(firstId);
    if (addTargetGroupId && filteredGroups.length > 0 && !filteredGroups.some((group) => getString(group, ['id'], '') === addTargetGroupId)) {
      setAddTargetGroupId(getString(filteredGroups[0], ['id'], ''));
    }
  }, [data.targetGroups, filteredGroups, addTargetGroupId]);

  const [showCreateGroup, setShowCreateGroup] = useState(false);
  const [showAddTarget, setShowAddTarget] = useState(false);

  const groupStatsById = new Map(
    businessServiceRows(data).map((row) => [row.groupId, row])
  );

  function extractRunVerdict(run: DataItem) {
    const verdictField = run.verdict;
    if (typeof verdictField === 'string' && verdictField) return verdictField;
    if (verdictField && typeof verdictField === 'object' && !Array.isArray(verdictField)) {
      return getString(verdictField as DataItem, ['verdict', 'status', 'result'], '');
    }
    return getString(run, ['verdict'], '');
  }

  function lastVerdictForGroup(groupId: string) {
    const latest = [...data.runs]
      .filter((run) => getString(run, ['target_group_id']) === groupId)
      .filter((run) => ['completed', 'verdicted'].includes(getString(run, ['status'])))
      .sort((left, right) =>
        String(right.started_at ?? right.created_at ?? '').localeCompare(String(left.started_at ?? left.created_at ?? ''))
      )[0];
    return latest ? extractRunVerdict(latest) : '';
  }

  function targetGroupVerdictBadgeTone(verdict: string): UiBadgeTone {
    const key = verdict.trim().toLowerCase();
    if (!key) return 'muted';
    if (['pass', 'passed', 'protected', 'success', 'ok'].includes(key)) return 'success';
    if (['gap', 'fail', 'failed', 'danger', 'penetrated', 'bypassable', 'unprotected'].includes(key)) return 'danger';
    if (['review', 'warn', 'warning', 'partial', 'inconclusive', 'manual_review'].includes(key)) return 'warn';
    return 'muted';
  }

  function formatTargetGroupVerdictLabel(verdict: string) {
    const key = verdict.trim().toLowerCase();
    if (!key) return 'None';
    if (['pass', 'passed', 'ok', 'success'].includes(key)) return 'Pass';
    if (['gap', 'fail', 'failed'].includes(key)) return 'Gap';
    if (['review', 'warn', 'partial', 'inconclusive', 'manual_review'].includes(key)) return 'Review';
    return formatPolicyVerdictLabel(verdict);
  }

  function criticalityBadgeTone(value: string): UiBadgeTone {
    if (value.trim().toLowerCase() === 'critical') return 'info';
    return value && value !== '—' ? 'muted' : 'muted';
  }

  function openFindingsBadgeTone(count: number): UiBadgeTone {
    if (count <= 0) return 'success';
    if (count >= 2) return 'danger';
    return 'warn';
  }

  const groupColumns: TableColumn<DataItem>[] = [
    {
      key: 'group',
      label: 'Group',
      render: (item) => <span className="mono">{getString(item, ['id'], '—')}</span>
    },
    {
      key: 'name',
      label: 'Name',
      render: (item) => getString(item, ['name'], '—')
    },
    {
      key: 'env',
      label: 'Env',
      render: (item) => <span className="mono">{getString(item, ['environment_id'], '—')}</span>
    },
    {
      key: 'criticality',
      label: 'Criticality',
      render: (item) => {
        const value = getString(item, ['criticality', 'business_criticality'], '');
        if (!value || value === '—') return <span className="muted">—</span>;
        const label = value.charAt(0).toUpperCase() + value.slice(1);
        return <Badge tone={criticalityBadgeTone(value)}>{label}</Badge>;
      }
    },
    {
      key: 'targets',
      label: 'Targets',
      render: (item) => formatNumber(getNumber(item, ['target_count']))
    },
    {
      key: 'agents',
      label: 'Agents',
      render: (item) => {
        const groupId = getString(item, ['id'], '');
        const stats = groupStatsById.get(groupId);
        const online = stats?.onlineAgents ?? 0;
        const total = stats?.boundAgents ?? 0;
        return <span className={`mono${total === 0 ? ' muted' : ''}`} title={total === 0 ? 'No agents bound to this group yet' : undefined}>{`${online}/${total}`}</span>;
      }
    },
    {
      key: 'runs',
      label: 'Runs',
      render: (item) => {
        const groupId = getString(item, ['id'], '');
        const runCount = data.runs.filter((run) => getString(run, ['target_group_id']) === groupId).length;
        return <span className="num">{formatNumber(runCount)}</span>;
      }
    },
    {
      key: 'open',
      label: 'Open',
      render: (item) => {
        const groupId = getString(item, ['id'], '');
        const open = groupStatsById.get(groupId)?.openFindings ?? 0;
        if (open === 0) return <Badge tone="success">0</Badge>;
        return <Badge tone={openFindingsBadgeTone(open)}>{formatNumber(open)}</Badge>;
      }
    },
    {
      key: 'last_verdict',
      label: 'Last verdict',
      render: (item) => {
        const groupId = getString(item, ['id'], '');
        const verdict = lastVerdictForGroup(groupId);
        return <Badge tone={targetGroupVerdictBadgeTone(verdict)}>{formatTargetGroupVerdictLabel(verdict)}</Badge>;
      }
    },
    {
      key: 'owner',
      label: 'Owner',
      render: (item) => {
        const owner = getString(item, ['owner', 'owner_group', 'business_owner'], '');
        return owner && owner !== '—' ? <span className="muted">{owner}</span> : <span className="muted">—</span>;
      }
    }
  ];

  async function runTargetAction<T>(label: string, action: () => Promise<T>, success: string) {
    setBusy(label);
    setError('');
    setMessage('');
    try {
      const result = await action();
      setMessage(success);
      await onRefresh();
      return result;
    } catch (err) {
      setError(apiErrorMessage(err, 'Action failed.'));
      return null;
    } finally {
      setBusy('');
    }
  }

  async function handleCreateGroup(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const formElement = event.currentTarget;
    const form = new FormData(formElement);
    const name = String(form.get('name') ?? '').trim();
    if (!name) {
      setError('Target group name is required.');
      return;
    }
    const formEnvironmentId = String(form.get('environment_id') ?? '').trim();
    const environmentId = (selectedEnvironmentId || formEnvironmentId).trim();
    if (!environmentId) {
      setError('Select an environment before creating a target group. Create one on the Environments page if none exist.');
      return;
    }
    const created = await runTargetAction('create-target-group', () => requestJson(config, session, '/v1/target-groups', {
      method: 'POST',
      body: {
        name,
        environment_id: environmentId,
        description: String(form.get('description') ?? '').trim(),
        timezone: String(form.get('timezone') ?? 'UTC').trim() || 'UTC',
        safety_policy: {
          max_concurrent_runs: Number(form.get('max_concurrent_runs') ?? 1),
          min_seconds_between_runs: Number(form.get('min_seconds_between_runs') ?? 300)
        }
      }
    }), 'Target group created from declared customer scope.');
    if (created && typeof created === 'object' && 'id' in created) {
      const id = String((created as { id: string }).id);
      setAddTargetGroupId(id);
      formElement.reset();
      setShowCreateGroup(false);
    }
  }

  async function handleAddTarget(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!effectiveGroupId) {
      setError('Create or select a target group before adding a target.');
      return;
    }
    const formElement = event.currentTarget;
    const form = new FormData(formElement);
    const value = String(form.get('value') ?? '').trim();
    if (!value) {
      setError('Target value is required.');
      return;
    }
    const added = await runTargetAction(`add-target-${effectiveGroupId}`, () => requestJson(config, session, `/v1/target-groups/${effectiveGroupId}/targets`, {
      method: 'POST',
      body: {
        kind: String(form.get('kind') ?? 'fqdn'),
        value
      }
    }), 'Declared target added to the selected group.');
    if (added) {
      formElement.reset();
      setShowAddTarget(false);
    }
  }

  return (
    <div className="content">
      <PageHeader
        route="target-groups"
        actions={
          <>
            <Button
              variant="secondary"
              size="sm"
              disabled={busy !== '' || filteredGroups.length === 0}
              onClick={() => {
                setError('');
                setMessage('');
                setShowAddTarget(true);
              }}
            >
              Add target
            </Button>
            <Button
              variant="default"
              size="sm"
              disabled={busy !== ''}
              onClick={() => {
                setError('');
                setMessage('');
                setShowCreateGroup(true);
              }}
            >
              Create target group
            </Button>
          </>
        }
      />
      {(message || error) && (
        <div className={error ? 'form-banner error' : 'form-banner'}>{error || message}</div>
      )}
      {environmentFilter ? (
        <div className="form-banner info row-actions">
          <span>Showing groups in environment <strong>{environmentFilter}</strong>.</span>
          <AnchorButton href="#target-groups" variant="ghost" size="sm">Clear filter</AnchorButton>
        </div>
      ) : null}
      <Card>
        <CardContent>
          <DataTable
            columns={groupColumns}
            items={filteredGroups}
            getRowId={(item) => getString(item, ['id'], '')}
            getRowProps={(item) => {
              const id = getString(item, ['id'], '');
              return id ? detailRowProps('target-group-detail', id, `Open target group ${id} detail`) : {};
            }}
            empty={emptyStateFromApi({
              icon: Target,
              meta: data.targetGroupsMeta,
              actionHref: readMetaAction(data.targetGroupsMeta, 'empty_action_href'),
              actionLabel: readMetaAction(data.targetGroupsMeta, 'empty_action_label')
            })}
          />
        </CardContent>
      </Card>
      <FormModal
        open={showCreateGroup}
        title="Create declared target group"
        description="Customers declare scope manually. AstraNull does not discover inventory automatically."
        onClose={() => setShowCreateGroup(false)}
      >
        {error ? <div className="form-banner error" role="alert">{error}</div> : null}
        <form className="product-form" onSubmit={handleCreateGroup}>
          <label>
            <span>Name</span>
            <input name="name" placeholder="Retail Checkout - Production" required autoFocus />
          </label>
          {environmentSelectOptions.length > 0 ? (
            <Select
              label="Environment"
              name="environment_id"
              value={selectedEnvironmentId}
              options={environmentSelectOptions}
              onChange={setSelectedEnvironmentId}
            />
          ) : (
            <label>
              <span>Environment</span>
              <input name="environment_id" placeholder="Create an environment first" defaultValue="" />
              <p className="muted full">No environments exist yet. Create one on the <AnchorButton href="#environments" variant="ghost" size="sm">Environments</AnchorButton> page, then declare a target group.</p>
            </label>
          )}
          <details className="full" open={showCreateMoreOptions} onToggle={(event) => setShowCreateMoreOptions((event.currentTarget as HTMLDetailsElement).open)}>
            <summary>More options</summary>
            <label className="full">
              <span>Description</span>
              <textarea name="description" rows={3} placeholder="Business service, owner, and known protection context." />
            </label>
            <label>
              <span>Timezone</span>
              <input name="timezone" defaultValue="UTC" />
            </label>
            <label>
              <span>Max concurrent runs</span>
              <input name="max_concurrent_runs" type="number" min="1" max="5" defaultValue="1" />
            </label>
            <label>
              <span>Cooldown between runs (seconds)</span>
              <input name="min_seconds_between_runs" type="number" min="60" defaultValue="300" />
            </label>
          </details>
          <div className="form-actions full">
            <Button type="button" variant="ghost" disabled={busy !== ''} onClick={() => setShowCreateGroup(false)}>Cancel</Button>
            <Button type="submit" loading={busy === 'create-target-group'}>Create group</Button>
          </div>
        </form>
      </FormModal>
      <FormModal
        open={showAddTarget}
        title="Add declared target"
        description="Add FQDN, URL, IP/port, DNS, or canary targets to the selected group."
        onClose={() => setShowAddTarget(false)}
      >
        {error ? <div className="form-banner error" role="alert">{error}</div> : null}
        <form className="product-form" onSubmit={handleAddTarget}>
          <input type="hidden" name="kind" value={addTargetKind} />
          <Select
            className="full"
            label="Selected group"
            value={effectiveGroupId}
            disabled={filteredGroups.length === 0}
            options={filteredGroups.length === 0
              ? [{ value: '', label: 'No target groups yet' }]
              : filteredGroups.map((group) => ({
                value: getString(group, ['id']),
                label: getString(group, ['name', 'id'])
              }))}
            onChange={setAddTargetGroupId}
          />
          <Select
            label="Target type"
            value={addTargetKind}
            options={TARGET_KIND_SELECT_OPTIONS}
            onChange={setAddTargetKind}
          />
          <label>
            <span>Value</span>
            <input name="value" placeholder="checkout.example.com" required autoFocus />
          </label>
          <div className="form-actions full">
            <Button type="button" variant="ghost" disabled={busy !== ''} onClick={() => setShowAddTarget(false)}>Cancel</Button>
            <Button type="submit" loading={busy.startsWith('add-target-')} disabled={busy !== '' || !effectiveGroupId}>Add target</Button>
          </div>
        </form>
      </FormModal>
    </div>
  );
}

export function GovernancePage({ route, data }: { route: RouteId; data: PortalData }) {
  const source =
    route === 'notifications' ? data.notificationRules :
      route === 'audit' ? data.audit :
        data.runs;
  const columns: TableColumn<DataItem>[] = [
    { key: 'id', label: 'Record', render: (item) => getString(item, ['title', 'name', 'id']) },
    { key: 'state', label: 'State', render: (item) => <Badge tone={getString(item, ['status', 'state'], 'recorded') === 'open' ? 'warn' : 'muted'}>{getString(item, ['status', 'state'], 'recorded')}</Badge> },
    { key: 'owner', label: 'Owner', render: (item) => getString(item, ['owner', 'actor_id', 'requested_by', 'created_by'], 'AstraNull') },
    { key: 'time', label: 'Time', render: (item) => formatDate(item.created_at ?? item.updated_at) }
  ];
  return (
    <div className="content">
      <PageHeader route={route} />
      <div className="metric-grid three">
        <MetricCard label="High-scale requests" value={data.highScale.length} sub="SOC controls required" icon={ShieldCheck} tone="muted" />
        <MetricCard label="Release evidence" value={data.releaseEvidence.length} sub="Metadata-only inventory" icon={FileText} tone="info" />
        <MetricCard label="Audit entries" value={formatNumber(data.audit.length)} sub="Security-relevant actions" icon={FileCheck2} tone="success" />
      </div>
      <Card>
        <CardHeader>
          <CardTitle>{ROUTE_BY_ID.get(route)?.label}</CardTitle>
          <CardDescription>Governance actions favor approval artifacts, custody, and fail-closed access boundaries.</CardDescription>
        </CardHeader>
        <CardContent>
          <DataTable
            columns={columns}
            items={source}
            empty={<EmptyState icon={ShieldCheck} title="No governance records yet." body="Requests, approvals, reports, and audit records appear here after controlled workflow activity." />}
          />
        </CardContent>
      </Card>
    </div>
  );
}

type ReportExportPreview = {
  reportId: string;
  format: string;
  title: string;
  contentSha256?: string;
  artifactId?: string;
  schemaVersion?: string;
  verification?: DataItem | null;
  textPreview?: string;
};

/**
 * Offline fallbacks only. The authoritative enums ship in `capabilities` on
 * `GET /v1/reports` (src/contracts/complianceReports.mjs); these arrays are used
 * when that payload has not loaded yet or came back empty.
 */
const REPORT_KIND_FALLBACK_OPTIONS: SelectOption[] = [
  { value: 'executive', label: 'Executive' },
  { value: 'board', label: 'Board' },
  { value: 'technical', label: 'Technical' },
  { value: 'soc', label: 'SOC' },
  { value: 'audit', label: 'Audit' },
  { value: 'soc2', label: 'SOC 2' },
  { value: 'iso27001', label: 'ISO 27001' },
  { value: 'dora', label: 'DORA' },
  { value: 'nis2', label: 'NIS2' },
  { value: 'internal_audit', label: 'Internal audit' }
];

const REPORT_FORMAT_FALLBACK_OPTIONS: SelectOption[] = [
  { value: 'json', label: 'JSON' },
  { value: 'markdown', label: 'Markdown' },
  { value: 'html', label: 'HTML' }
];

const REPORT_PERIOD_FALLBACK_OPTIONS: SelectOption[] = [
  { value: 'last-7-days', label: 'Last 7 days' },
  { value: 'last-30-days', label: 'Last 30 days' },
  { value: 'quarter', label: 'Current quarter' },
  { value: 'all-time', label: 'All time' }
];

function humanizeOptionValue(value: string) {
  const spaced = value.replace(/[_-]+/g, ' ').trim();
  return spaced ? spaced.charAt(0).toUpperCase() + spaced.slice(1) : value;
}

export function reportOptionsFromCapabilities(
  capabilities: DataItem | null | undefined,
  key: 'kinds' | 'formats' | 'periods',
  fallback: SelectOption[]
): SelectOption[] {
  const raw = capabilities?.[key];
  if (!Array.isArray(raw)) return fallback;
  const options: SelectOption[] = [];
  for (const entry of raw) {
    if (typeof entry === 'string') {
      if (entry) options.push({ value: entry, label: humanizeOptionValue(entry) });
      continue;
    }
    if (!entry || typeof entry !== 'object') continue;
    const item = entry as DataItem;
    const value = getString(item, ['value', 'kind', 'format', 'period', 'id'], '');
    if (!value) continue;
    options.push({ value, label: getString(item, ['label', 'title', 'name'], humanizeOptionValue(value)) });
  }
  return options.length ? options : fallback;
}

function clampOptionValue(options: SelectOption[], value: string) {
  if (options.some((option) => option.value === value)) return value;
  return options[0]?.value ?? value;
}

export function ReportsPage({
  data,
  config,
  session,
  onRefresh
}: {
  data: PortalData;
  config: PortalConfig;
  session: Session;
  onRefresh: () => Promise<void>;
}) {
  const [busy, setBusy] = useState('');
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');
  const [preview, setPreview] = useState<ReportExportPreview | null>(null);
  const [reportKind, setReportKind] = useState('technical');
  const [reportFormat, setReportFormat] = useState('json');
  const [reportPeriod, setReportPeriod] = useState('last-30-days');
  const reports = data.reports;
  const reportKindOptions = reportOptionsFromCapabilities(
    data.reportCapabilities,
    'kinds',
    REPORT_KIND_FALLBACK_OPTIONS
  );
  const reportFormatOptions = reportOptionsFromCapabilities(
    data.reportCapabilities,
    'formats',
    REPORT_FORMAT_FALLBACK_OPTIONS
  );
  const reportPeriodOptions = reportOptionsFromCapabilities(
    data.reportCapabilities,
    'periods',
    REPORT_PERIOD_FALLBACK_OPTIONS
  );
  // A stale selection must never be submitted once the backend drops an enum value.
  const selectedReportKind = clampOptionValue(reportKindOptions, reportKind);
  const selectedReportFormat = clampOptionValue(reportFormatOptions, reportFormat);
  const selectedReportPeriod = clampOptionValue(reportPeriodOptions, reportPeriod);
  const reportExports = data.audit.filter((entry) => getString(entry, ['action'], '') === 'report.exported').length;
  const reportColumns: TableColumn<DataItem>[] = [
    { key: 'report', label: 'Report', render: (item) => <span className="mono">{getString(item, ['id'], '—')}</span> },
    { key: 'kind', label: 'Kind', render: (item) => <span className="mono">{getString(item, ['kind'], '—')}</span> },
    {
      key: 'period',
      label: 'Period',
      render: (item) => {
        const value = getString(item, ['period', 'reporting_period', 'window'], '');
        if (!value) return <span className="muted">—</span>;
        const label = reportPeriodOptions.find((option) => option.value === value)?.label ?? humanizeOptionValue(value);
        return <span className="muted">{label}</span>;
      }
    },
    { key: 'format', label: 'Format', render: (item) => <span className="mono">{getString(item, ['format', 'export_format'], '—')}</span> },
    { key: 'generated', label: 'Generated', render: (item) => <span className="muted">{formatDate(item.created_at ?? item.generated_at)}</span> }
  ];

  async function runReportAction<T>(label: string, action: () => Promise<T>, success: string) {
    setBusy(label);
    setError('');
    setMessage('');
    try {
      const result = await action();
      setMessage(success);
      return result;
    } catch (err) {
      setError(apiErrorMessage(err, 'Report action failed.'));
      return null;
    } finally {
      setBusy('');
    }
  }

  async function handleCreateReport(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const kind = selectedReportKind || 'technical';
    const format = (selectedReportFormat || 'json') as 'json' | 'markdown' | 'html';
    const created = await runReportAction('create-report', () => requestJson(config, session, '/v1/reports', {
      method: 'POST',
      body: { title: `AstraNull ${kind} readiness report`, kind, format, period: selectedReportPeriod }
    }), 'Report generated.');
    if (created && typeof created === 'object') {
      await onRefresh();
      const id = getString(created as DataItem, ['id'], '');
      if (id) {
        setMessage(`Report generated — exporting ${format.toUpperCase()} with custody metadata.`);
        await exportReport(id, format);
      }
    }
  }

  async function exportReport(reportId: string, format: 'json' | 'markdown' | 'html') {
    if (!reportId) return;
    await runReportAction(`export-${reportId}-${format}`, async () => {
      const headers = buildApiHeaders(config, session);
      const response = await fetch(`/v1/reports/${encodeURIComponent(reportId)}/export?format=${format}`, { headers });
      const contentType = response.headers.get('content-type') ?? '';
      if (!response.ok) {
        const payload = await response.json().catch(() => null);
        throw new Error(
          String(payload?.message ?? '').trim()
            || humanizeErrorCode(payload?.error)
            || `Export returned ${response.status}`
        );
      }
      const triggerDownload = (content: string, mime: string) => {
        try {
          const ext = format === 'markdown' ? 'md' : format;
          const blob = new Blob([content], { type: mime });
          const url = URL.createObjectURL(blob);
          const anchor = document.createElement('a');
          anchor.href = url;
          anchor.download = `${reportId}.${ext}`;
          document.body.appendChild(anchor);
          anchor.click();
          anchor.remove();
          setTimeout(() => URL.revokeObjectURL(url), 0);
        } catch { /* download is best-effort; preview still renders */ }
      };
      if (format === 'json' || contentType.includes('application/json')) {
        const exported = await response.json();
        const custody = getNestedItem(exported, ['custody']);
        const payload = getNestedItem(exported, ['payload']);
        let verification: DataItem | null = null;
        if (custody && payload) {
          const verified = await requestJson(config, session, '/v1/custody/verify', {
            method: 'POST',
            body: { payload, custody }
          });
          verification = getNestedItem(verified as DataItem, ['verification']) ?? verified as DataItem;
        }
        setPreview({
          reportId,
          format,
          title: getNestedString(payload, ['title'], getString(reports.find((report) => getString(report, ['id'], '') === reportId) ?? {}, ['title'], reportId)),
          contentSha256: getString(custody ?? {}, ['content_sha256'], ''),
          artifactId: getString(custody ?? {}, ['artifact_id'], ''),
          schemaVersion: getString(custody ?? {}, ['schema_version'], ''),
          verification
        });
        triggerDownload(JSON.stringify(exported, null, 2), 'application/json');
        await onRefresh();
        return exported;
      }
      const textPayload = await response.text();
      setPreview({
        reportId,
        format,
        title: getString(reports.find((report) => getString(report, ['id'], '') === reportId) ?? {}, ['title'], reportId),
        textPreview: textPayload.slice(0, 900)
      });
      triggerDownload(textPayload, format === 'markdown' ? 'text/markdown' : 'text/html');
      await onRefresh();
      return textPayload;
    }, `Report exported as ${format}.`);
  }

  return (
    <div className="content">
      <PageHeader
        route="reports"
      />
      <PageContextSummary>
        <span className="tabular-nums">{reports.length}</span> reports ·{' '}
        <span className="tabular-nums">{reportExports}</span> custody exports recorded
      </PageContextSummary>
      {(message || error) && (
        <div className={error ? 'form-banner error' : 'form-banner'}>
          {error || message}
        </div>
      )}
      <Card>
        <CardHeader>
          <CardTitle>Generate report</CardTitle>
          <CardDescription>Create a tenant-scoped report from current readiness, run, finding, and compliance mapping data. Generating a report also exports the selected format with custody metadata.</CardDescription>
        </CardHeader>
        <CardContent>
          <form className="product-form" onSubmit={handleCreateReport} aria-busy={busy === 'create-report' || undefined}>
            <Select label="Kind" name="kind" value={selectedReportKind} options={reportKindOptions} onChange={setReportKind} />
            <Select label="Format" name="format" value={selectedReportFormat} options={reportFormatOptions} onChange={setReportFormat} />
            <Select label="Period" name="period" value={selectedReportPeriod} options={reportPeriodOptions} onChange={setReportPeriod} />
            <div className="form-actions full">
              <Button type="submit" loading={busy === 'create-report'}>Generate &amp; export</Button>
              <span className="muted text-xs">PDF returns <span className="mono">unsupported_format</span>. Use HTML-to-PDF in your review toolchain.</span>
            </div>
          </form>
        </CardContent>
      </Card>
      <Card>
        <PanelCardHeader title="Recent reports" />
        <CardContent aria-busy={busy.startsWith('export-') || busy === 'create-report' || undefined}>
          <DataTable
            columns={reportColumns}
            items={reports}
            getRowId={(item) => getString(item, ['id'], '')}
            getRowProps={(item) => {
              const id = getString(item, ['id'], '');
              return id ? detailRowProps('report-detail', id, `Open report ${id} detail`) : {};
            }}
            empty={<EmptyState icon={FileText} title="No reports generated." body="Generate a report after validation activity to create a custody-ready evidence artifact." />}
          />
        </CardContent>
      </Card>
    </div>
  );
}

function expiresAtFromForm(value: string) {
  const now = Date.now();
  if (value === '15m') return new Date(now + 15 * 60 * 1000).toISOString();
  if (value === '1h') return new Date(now + 60 * 60 * 1000).toISOString();
  if (value === '24h') return new Date(now + 24 * 60 * 60 * 1000).toISOString();
  if (value === '30d') return new Date(now + 30 * 24 * 60 * 60 * 1000).toISOString();
  return null;
}

type SettingsTab = 'organization' | 'access' | 'security' | 'privacy';

const SETTINGS_TAB_OPTIONS: { id: SettingsTab; label: string }[] = [
  { id: 'organization', label: 'Organization' },
  { id: 'access', label: 'Access' },
  { id: 'security', label: 'Security' },
  { id: 'privacy', label: 'Privacy' }
];

function readOidcPosture(config: PortalConfig) {
  const siteConfig = config.siteConfig;
  const issuer = getNestedString(siteConfig, ['oidc', 'issuer'], '')
    || getString(siteConfig, ['oidc_issuer'], '');
  const audience = getNestedString(siteConfig, ['oidc', 'audience'], '')
    || getString(siteConfig, ['oidc_audience'], '');
  return {
    authMode: config.authMode,
    issuer: issuer && issuer !== '—' ? issuer : null,
    audience: audience && audience !== '—' ? audience : null,
    bundledStagingLogin: config.bundledLoginEnabled
  };
}

export function SettingsPage({
  data,
  config,
  session,
  onRefresh
}: {
  data: PortalData;
  config: PortalConfig;
  session: Session;
  onRefresh: () => Promise<void>;
}) {
  const [tab, setTab] = useState<SettingsTab>('organization');
  const [busy, setBusy] = useState('');
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');
  const [oneTimeSecret, setOneTimeSecret] = useState<{ label: string; value: string } | null>(null);
  const [rotateSecretId, setRotateSecretId] = useState('');
  const [bootstrapTargetGroupId, setBootstrapTargetGroupId] = useState('');
  const [bootstrapExpiry, setBootstrapExpiry] = useState('1h');
  const [pendingRetention, setPendingRetention] = useState<{
    metadata_retention_days: number;
    evidence_retention: {
      report_days: number;
      audit_log_days: number;
      high_scale_artifact_days: number;
      legal_hold: boolean;
    };
  } | null>(null);
  const tenant = data.tenant;
  const bootstrapTargetGroupOptions: SelectOption[] = [
    { value: '', label: 'No default binding' },
    ...data.targetGroups.map((group) => ({
      value: getString(group, ['id']),
      label: getString(group, ['name', 'id'])
    }))
  ];
  const privacy = getNestedItem(tenant, ['privacy_settings']) ?? {};
  const evidenceRetention = getNestedItem(privacy, ['evidence_retention']) ?? {};
  const metadataRetentionDays = getNumber(privacy, ['metadata_retention_days'], 90);
  const oidcPosture = readOidcPosture(config);
  const routeAccessContext = {
    principal: session.principal,
    staffRole: session.staff_role,
  };
  const role = session.role ?? 'admin';
  const canReadAudit = canAccessRoute(role, 'audit', routeAccessContext);
  const canReadNotifications = canAccessRoute(role, 'notifications', routeAccessContext);
  const settingsTabOptions = SETTINGS_TAB_OPTIONS;
  const tokenColumns: TableColumn<DataItem>[] = [
    { key: 'name', label: 'Token', render: (item) => getString(item, ['name', 'id']) },
    { key: 'environment', label: 'Environment', render: (item) => getString(item, ['environment_id']) },
    { key: 'usage', label: 'Usage', render: (item) => `${getNumber(item, ['registrations_used'])}/${getNumber(item, ['max_registrations'], 1)}` },
    { key: 'expires', label: 'Expires', render: (item) => formatDate(item.expires_at) },
    { key: 'state', label: 'State', render: (item) => <Badge tone={item.revoked_at ? 'muted' : 'success'}>{item.revoked_at ? 'revoked' : 'active'}</Badge> },
    {
      key: 'actions',
      label: 'Actions',
      render: (item) => {
        const id = getString(item, ['id'], '');
        return <Button size="sm" variant="danger" disabled={busy !== '' || Boolean(item.revoked_at)} onClick={() => void revokeBootstrapToken(id)}>Revoke</Button>;
      }
    }
  ];
  const serviceAccountColumns: TableColumn<DataItem>[] = [
    { key: 'name', label: 'Account', render: (item) => getString(item, ['name', 'id']) },
    { key: 'role', label: 'Role', render: (item) => <Badge tone="info">{getString(item, ['role'])}</Badge> },
    { key: 'scopes', label: 'Scopes', render: (item) => Array.isArray(item.scopes) ? item.scopes.join(', ') : 'role defaults' },
    { key: 'expires', label: 'Expires', render: (item) => item.expires_at ? formatDate(item.expires_at) : 'No expiry' },
    { key: 'state', label: 'State', render: (item) => <Badge tone={item.revoked_at ? 'muted' : 'success'}>{item.revoked_at ? 'revoked' : 'active'}</Badge> },
    {
      key: 'actions',
      label: 'Actions',
      render: (item) => {
        const id = getString(item, ['id'], '');
        return (
          <div className="row-actions">
            <Button size="sm" variant="secondary" disabled={busy !== '' || Boolean(item.revoked_at)} onClick={() => void rotateServiceAccount(id)}>Rotate</Button>
            <Button size="sm" variant="danger" disabled={busy !== '' || Boolean(item.revoked_at)} onClick={() => void revokeServiceAccount(id)}>Revoke</Button>
          </div>
        );
      }
    }
  ];

  async function runSettingsAction<T>(label: string, action: () => Promise<T>, success: string) {
    setBusy(label);
    setError('');
    setMessage('');
    try {
      const result = await action();
      setMessage(success);
      await onRefresh();
      return result;
    } catch (err) {
      setError(apiErrorMessage(err, 'Action failed.'));
      return null;
    } finally {
      setBusy('');
    }
  }

  async function handleCreateBootstrapToken(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const formElement = event.currentTarget;
    const form = new FormData(formElement);
    const name = String(form.get('name') ?? '').trim() || 'Install token';
    const expiry = expiresAtFromForm(String(form.get('expiry') ?? '1h'));
    const maxRegistrations = Number(form.get('max_registrations') ?? 1);
    const targetGroupId = String(form.get('target_group_id') ?? '').trim();
    const result = await runSettingsAction('create-bootstrap-token', () => requestJson(config, session, '/v1/bootstrap-tokens', {
      method: 'POST',
      body: {
        name,
        environment_id: String(form.get('environment_id') ?? 'env_demo'),
        ...(targetGroupId ? { target_group_id: targetGroupId } : {}),
        max_registrations: Number.isFinite(maxRegistrations) && maxRegistrations > 0 ? maxRegistrations : 1,
        ...(expiry ? { expires_at: expiry } : {})
      }
    }), 'Bootstrap token created. Copy the secret now; it is shown once.');
    if (result && typeof result === 'object' && 'secret' in result && typeof (result as { secret?: unknown }).secret === 'string') {
      setOneTimeSecret({ label: 'Bootstrap token secret', value: String((result as { secret: string }).secret) });
      formElement.reset();
    }
  }

  async function handleCreateServiceAccount(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const formElement = event.currentTarget;
    const form = new FormData(formElement);
    const requestedScopes = String(form.get('scopes') ?? '')
      .split(',')
      .map((scope) => scope.trim())
      .filter(Boolean);
    const scopes = requestedScopes.length ? requestedScopes : ['tenant:read'];
    const result = await runSettingsAction('create-service-account', () => requestJson(config, session, '/v1/service-accounts', {
      method: 'POST',
      body: {
        name: String(form.get('name') ?? '').trim() || 'Automation account',
        role: String(form.get('role') ?? 'viewer'),
        scopes,
        ...(expiresAtFromForm(String(form.get('expiry') ?? '')) ? { expires_at: expiresAtFromForm(String(form.get('expiry') ?? '')) } : {})
      }
    }), 'Service account created. Copy the API secret now; it is shown once.');
    if (result && typeof result === 'object' && 'secret' in result && typeof (result as { secret?: unknown }).secret === 'string') {
      setOneTimeSecret({ label: 'Service API secret', value: String((result as { secret: string }).secret) });
      formElement.reset();
    }
  }

  async function revokeBootstrapToken(id: string) {
    if (!id) return;
    if (!window.confirm('Revoke this bootstrap token? New agent registrations using it will fail.')) return;
    await runSettingsAction(`revoke-bootstrap-${id}`, () => requestJson(config, session, `/v1/bootstrap-tokens/${id}/revoke`, { method: 'POST' }), 'Bootstrap token revoked.');
  }

  async function revokeServiceAccount(id: string) {
    if (!id) return;
    if (!window.confirm('Revoke this service account? API calls using its secret will stop working.')) return;
    await runSettingsAction(`revoke-service-${id}`, () => requestJson(config, session, `/v1/service-accounts/${id}/revoke`, { method: 'POST' }), 'Service account revoked.');
  }

  async function rotateServiceAccount(id: string) {
    if (!id) return;
    if (!window.confirm('Rotate this service account? The current API secret will stop working immediately.')) return;
    const result = await runSettingsAction(`rotate-service-${id}`, () => requestJson(config, session, `/v1/service-accounts/${id}/rotate`, { method: 'POST' }), 'Service account rotated. Copy the new API secret now; it is shown once.');
    if (result && typeof result === 'object' && 'secret' in result && typeof (result as { secret?: unknown }).secret === 'string') {
      setOneTimeSecret({ label: 'Rotated service API secret', value: String((result as { secret: string }).secret) });
    }
  }

  async function handleSaveOrganization(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const name = String(form.get('name') ?? '').trim();
    if (!name) {
      setError('Organization name is required.');
      return;
    }
    await runSettingsAction('save-organization', () => requestJson(config, session, '/v1/tenants/current', {
      method: 'PATCH',
      body: { name }
    }), 'Organization settings saved.');
  }

  function handleSaveRetention(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    // Read the form here, not in the confirm handler: `currentTarget` is null once this
    // synchronous handler returns, and the modal resolves long after that.
    const form = new FormData(event.currentTarget);
    setPendingRetention({
      metadata_retention_days: Number(form.get('metadata_retention_days') ?? 90),
      evidence_retention: {
        report_days: Number(form.get('report_days') ?? 365),
        audit_log_days: Number(form.get('audit_log_days') ?? 2555),
        high_scale_artifact_days: Number(form.get('high_scale_artifact_days') ?? 2555),
        legal_hold: form.get('legal_hold') === 'on'
      }
    });
  }

  async function confirmSaveRetention() {
    const privacySettings = pendingRetention;
    if (!privacySettings) return;
    await runSettingsAction('save-retention', () => requestJson(config, session, '/v1/tenants/current', {
      method: 'PATCH',
      body: { privacy_settings: privacySettings }
    }), 'Retention policy saved. Metadata purge runs immediately when retention days change.');
    setPendingRetention(null);
  }

  async function handleCreateVaultSecret(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const formElement = event.currentTarget;
    const form = new FormData(formElement);
    const purpose = String(form.get('purpose') ?? '').trim();
    const name = String(form.get('name') ?? '').trim();
    const plaintext = String(form.get('plaintext') ?? '').trim();
    if (!purpose || !name || !plaintext) {
      setError('Purpose, name, and credential value are required.');
      return;
    }
    if (!window.confirm('Store this integration secret? Authorized internal workflows will use the new credential.')) return;
    await runSettingsAction('create-vault-secret', () => requestJson(config, session, '/v1/secrets', {
      method: 'POST',
      body: {
        purpose,
        name,
        plaintext,
        metadata: { source: 'settings_vault' }
      }
    }), 'Integration secret stored. Plaintext is never returned by list APIs.');
    formElement.reset();
  }

  async function handleRotateVaultSecret(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const formElement = event.currentTarget;
    const form = new FormData(formElement);
    const id = String(form.get('secret_id') ?? rotateSecretId).trim();
    const plaintext = String(form.get('plaintext') ?? '').trim();
    if (!id || !plaintext) {
      setError('Select a secret and provide the replacement credential value.');
      return;
    }
    if (!window.confirm('Rotate this vault secret? The current credential will stop working for authorized internal workflows.')) return;
    await runSettingsAction(`rotate-vault-${id}`, () => requestJson(config, session, `/v1/secrets/${id}/rotate`, {
      method: 'POST',
      body: { plaintext }
    }), 'Secret rotated. Prior credential stops working for authorized internal workflows.');
    formElement.reset();
    setRotateSecretId('');
  }

  const secretColumns: TableColumn<DataItem>[] = [
    { key: 'name', label: 'Name', render: (item) => getString(item, ['name', 'id']) },
    { key: 'purpose', label: 'Purpose', render: (item) => <Badge tone="info">{getString(item, ['purpose'])}</Badge> },
    { key: 'rotation', label: 'Rotation', render: (item) => getNumber(item, ['rotation']) },
    { key: 'updated', label: 'Updated', render: (item) => formatDate(item.updated_at ?? item.created_at) },
    {
      key: 'actions',
      label: 'Actions',
      render: (item) => {
        const id = getString(item, ['id'], '');
        return (
          <Button
            size="sm"
            variant="secondary"
            disabled={busy !== ''}
            onClick={() => {
              setRotateSecretId(id);
              setTab('security');
            }}
          >
            Rotate
          </Button>
        );
      }
    }
  ];

  return (
    <div className="content">
      <PageHeader
        route="settings"
        eyebrow="Tenant configuration"
      />
      <PageContextSummary>
        {getString(tenant ?? {}, ['name'], 'Organization')} ·{' '}
        <span className="tabular-nums">{data.secrets.length}</span> vault secrets ·{' '}
        <span className="tabular-nums">{metadataRetentionDays}</span>d metadata retention
      </PageContextSummary>
      <Tabs value={tab} options={settingsTabOptions} onChange={setTab} className="tabs-wrap" />
      {(message || error) && (
        <div className={error ? 'form-banner error' : 'form-banner'}>
          {error || message}
        </div>
      )}
      {oneTimeSecret && (
        <Card className="secret-card">
          <PanelCardHeader
            title={oneTimeSecret.label}
            description="This value is shown once. It is not returned by list APIs and will not be visible after refresh."
            trailing={
              <div className="row-actions">
                <Button
                  variant="secondary"
                  size="sm"
                  onClick={() => {
                    void navigator.clipboard.writeText(oneTimeSecret.value).then(() => {
                      setMessage('Secret copied to clipboard.');
                      setError('');
                    }).catch(() => {
                      setError('Clipboard copy failed. Select the secret manually.');
                    });
                  }}
                >
                  Copy secret
                </Button>
                <Button variant="ghost" size="sm" onClick={() => setOneTimeSecret(null)}>Dismiss</Button>
              </div>
            }
          />
          <CardContent>
            <pre className="codeblock">{oneTimeSecret.value}</pre>
          </CardContent>
        </Card>
      )}

      {tab === 'organization' && (
        <>
        <div className="split">
          <Card>
            <CardHeader>
              <CardTitle>Organization profile</CardTitle>
              <CardDescription>Organization display name and residency metadata. Privacy defaults stay metadata-only.</CardDescription>
            </CardHeader>
            <CardContent>
              {tenant ? (
                <form className="product-form" onSubmit={handleSaveOrganization}>
                  <label className="full">
                    <span>Organization name</span>
                    <input name="name" defaultValue={getString(tenant, ['name'])} required />
                  </label>
                  <label>
                    <span>Tenant ID</span>
                    <input value={getString(tenant, ['id'])} readOnly />
                  </label>
                  <label>
                    <span>Data region</span>
                    <input value={getString(tenant, ['data_region'], 'unrecorded')} readOnly />
                  </label>
                  <div className="form-actions full">
                    <Button type="submit" loading={busy === 'save-organization'}>Save organization</Button>
                  </div>
                </form>
              ) : (
                <EmptyState
                  icon={ShieldCheck}
                  variant="skeleton"
                  title="Organization profile loading…"
                  body="Tenant settings are not available yet for this session. Refresh the page or retry in a moment."
                  actionLabel="Refresh page"
                  onAction={() => window.location.reload()}
                />
              )}
            </CardContent>
          </Card>
          <Card>
            <CardHeader>
              <CardTitle>Workspace inventory</CardTitle>
              <CardDescription>Live workspace counts — not editable here.</CardDescription>
            </CardHeader>
            <CardContent className="kv-list">
              <div><span>Target groups</span><strong>{data.targetGroups.length}</strong></div>
              <div><span>Agents</span><strong>{data.agents.length}</strong></div>
              <div><span>Evidence records</span><strong>{data.evidence.length}</strong></div>
              <div><span>Environments</span><strong>{new Set(data.targetGroups.map((group) => getString(group, ['environment_id'], 'unassigned'))).size}</strong></div>
            </CardContent>
          </Card>
        </div>
        <Card>
          <CardHeader>
            <CardTitle>Session &amp; access posture</CardTitle>
            <CardDescription>Read-only session view. User invites and enterprise SSO mapping are provisioned by AstraNull support.</CardDescription>
          </CardHeader>
          <CardContent className="kv-list">
            <div><span>User ID</span><strong>{session.user_id ?? '—'}</strong></div>
            <div><span>Role</span><strong>{session.role ?? '—'}</strong></div>
            <div><span>Tenant</span><strong>{session.tenant_id ?? data.state?.tenant_id ?? '—'}</strong></div>
            <div><span>Auth mode</span><strong>{config.authMode}</strong></div>
          </CardContent>
          <CardContent className="settings-list">
            <SettingsNote icon={ShieldCheck}>Tenant user invites and role changes are not self-service on this screen.</SettingsNote>
            <SettingsNote icon={FileCheck2}>API credentials live under Access; vault secrets under Security; audit history on the Audit page.</SettingsNote>
          </CardContent>
          {session.principal === 'staff' ? (
            <CardContent className="row-actions">
              <AnchorButton href="#admin" variant="secondary" size="sm">Staff admin console</AnchorButton>
            </CardContent>
          ) : null}
        </Card>
        {canReadAudit ? (
          <Card>
            <PanelCardHeader
              title="Tenant audit log"
              description="Immutable security-relevant history lives on the Audit page — Settings does not duplicate that log."
              trailing={<AnchorButton href="#audit" variant="secondary" size="sm">Open audit log</AnchorButton>}
            />
            <CardContent className="row-actions">
              {canReadNotifications ? <AnchorButton href="#notifications" variant="ghost" size="sm">Notification rules</AnchorButton> : null}
              <AnchorButton href="#integrations" variant="ghost" size="sm">Integrations</AnchorButton>
            </CardContent>
          </Card>
        ) : null}
        </>
      )}

      {tab === 'access' && (
        <>
          <div className="split">
            <Card>
              <CardHeader>
                <CardTitle>Create bootstrap token</CardTitle>
                <CardDescription>Issue a short-lived one-time install secret for outbound agent registration.</CardDescription>
              </CardHeader>
              <CardContent>
                <form className="product-form" onSubmit={handleCreateBootstrapToken}>
                  <label>
                    <span>Name</span>
                    <input name="name" placeholder="prod-edge-install" />
                  </label>
                  <label>
                    <span>Environment</span>
                    <input name="environment_id" defaultValue="env_demo" />
                  </label>
                  <input type="hidden" name="target_group_id" value={bootstrapTargetGroupId} />
                  <input type="hidden" name="expiry" value={bootstrapExpiry} />
                  <Select
                    label="Target group"
                    value={bootstrapTargetGroupId}
                    options={bootstrapTargetGroupOptions}
                    onChange={setBootstrapTargetGroupId}
                  />
                  <Select
                    label="Expiry"
                    value={bootstrapExpiry}
                    options={BOOTSTRAP_EXPIRY_OPTIONS}
                    onChange={setBootstrapExpiry}
                  />
                  <label>
                    <span>Max registrations</span>
                    <input name="max_registrations" type="number" min="1" max="50" defaultValue="1" />
                  </label>
                  <div className="form-actions full">
                    <Button type="submit" loading={busy === 'create-bootstrap-token'}>Create token</Button>
                  </div>
                </form>
              </CardContent>
            </Card>
            <Card>
              <CardHeader>
                <CardTitle>Create service account</CardTitle>
                <CardDescription>Create scoped API automation credentials. Secrets are returned once and list views stay redacted.</CardDescription>
              </CardHeader>
              <CardContent>
                <form className="product-form" onSubmit={handleCreateServiceAccount}>
                  <label>
                    <span>Name</span>
                    <input name="name" placeholder="ci-evidence-reader" />
                  </label>
                  <label>
                    <span>Role</span>
                    <select name="role" defaultValue="viewer">
                      <option value="viewer">Viewer</option>
                      <option value="auditor">Auditor</option>
                      <option value="engineer">Engineer</option>
                      <option value="admin">Admin</option>
                    </select>
                  </label>
                  <label className="full">
                    <span>Scopes</span>
                    <input name="scopes" defaultValue="tenant:read,evidence:read" />
                  </label>
                  <label>
                    <span>Expiry</span>
                    <select name="expiry" defaultValue="">
                      <option value="">No expiry</option>
                      <option value="24h">24 hours</option>
                      <option value="30d">30 days</option>
                    </select>
                  </label>
                  <div className="form-actions full">
                    <Button type="submit" loading={busy === 'create-service-account'}>Create API key</Button>
                  </div>
                </form>
              </CardContent>
            </Card>
          </div>
          <Card>
            <PanelCardHeader
              title="Bootstrap tokens"
              description="Install tokens are redacted after creation and can be revoked immediately."
              trailing={<Badge tone="info">{data.bootstrapTokens.length} records</Badge>}
            />
            <CardContent>
              <DataTable
                columns={tokenColumns}
                items={data.bootstrapTokens}
                empty={<EmptyState icon={KeyRound} title="No bootstrap tokens." body="Create a short-lived token before installing an outbound-only agent." />}
              />
            </CardContent>
          </Card>
          <Card>
            <PanelCardHeader
              title="Service accounts"
              description="Automation credentials are scoped, auditable, rotatable, and redacted after creation."
              trailing={<Badge tone="success">{data.serviceAccounts.length} records</Badge>}
            />
            <CardContent>
              <DataTable
                columns={serviceAccountColumns}
                items={data.serviceAccounts}
                empty={<EmptyState icon={UserCog} title="No service accounts." body="Create an API key only for a clear automation owner and scope." />}
              />
            </CardContent>
          </Card>
        </>
      )}

      {tab === 'security' && (
        <>
          <Card>
            <CardHeader>
              <CardTitle>Enterprise SSO posture</CardTitle>
              <CardDescription>Read-only sign-in configuration for this deployment. Secrets and JWKS URLs are never exposed.</CardDescription>
            </CardHeader>
            <CardContent className="kv-list">
              <div><span>Auth mode</span><strong>{oidcPosture.authMode}</strong></div>
              <div><span>OIDC issuer</span><strong>{oidcPosture.issuer ?? 'Not exposed on public readiness endpoints'}</strong></div>
              <div><span>OIDC audience</span><strong>{oidcPosture.audience ?? 'Not exposed on public readiness endpoints'}</strong></div>
              <div><span>Bundled staging login</span><strong>{oidcPosture.bundledStagingLogin ? 'Enabled' : 'Disabled'}</strong></div>
              <div><span>Login URL</span><strong>{config.loginUrl}</strong></div>
            </CardContent>
            <CardContent className="settings-list">
              <SettingsNote icon={ShieldCheck}>Production human auth defaults to `oidc-jwt` with JWKS verification; developer validation may use `dev-headers` or bundled staging login.</SettingsNote>
              <SettingsNote icon={KeyRound}>Issuer and audience values are configured server-side. Public site-config currently exposes `auth_mode` only unless your deployment extends the payload.</SettingsNote>
            </CardContent>
          </Card>
          <div className="split">
            <Card>
              <CardHeader>
                <CardTitle>Store integration secret</CardTitle>
                <CardDescription>Plaintext is accepted only on create/rotate. List APIs return metadata-only envelopes.</CardDescription>
              </CardHeader>
              <CardContent>
                <form className="product-form" onSubmit={handleCreateVaultSecret}>
                  <label>
                    <span>Purpose</span>
                    <select name="purpose" defaultValue="integration_credential">
                      <option value="integration_credential">Integration credential</option>
                      <option value="waf_connector">WAF connector</option>
                      <option value="webhook_signing">Webhook signing</option>
                      <option value="provider_api">Provider API</option>
                    </select>
                  </label>
                  <label>
                    <span>Name</span>
                    <input name="name" placeholder="cloudflare:edge-readonly" required />
                  </label>
                  <label className="full">
                    <span>Credential value</span>
                    <textarea name="plaintext" rows={4} placeholder="API token or JSON credential" required />
                  </label>
                  <div className="form-actions full">
                    <Button type="submit" loading={busy === 'create-vault-secret'}>Store secret</Button>
                  </div>
                </form>
              </CardContent>
            </Card>
            <Card>
              <CardHeader>
                <CardTitle>Rotate stored secret</CardTitle>
                <CardDescription>Rotation replaces the encrypted envelope; plaintext is never returned after storage.</CardDescription>
              </CardHeader>
              <CardContent>
                <form className="product-form" onSubmit={handleRotateVaultSecret}>
                  <label className="full">
                    <span>Secret</span>
                    <select name="secret_id" value={rotateSecretId} onChange={(event) => setRotateSecretId(event.target.value)} required>
                      <option value="">Select secret</option>
                      {data.secrets.map((secret) => (
                        <option key={getString(secret, ['id'])} value={getString(secret, ['id'])}>
                          {getString(secret, ['name'])} · {getString(secret, ['purpose'])}
                        </option>
                      ))}
                    </select>
                  </label>
                  <label className="full">
                    <span>Replacement credential</span>
                    <textarea name="plaintext" rows={4} placeholder="New API token or JSON credential" required />
                  </label>
                  <div className="form-actions full">
                    <Button type="submit" disabled={busy !== '' || data.secrets.length === 0}>Rotate secret</Button>
                  </div>
                </form>
              </CardContent>
            </Card>
          </div>
          <Card>
            <PanelCardHeader
              title="Secret vault inventory"
              description="Stored secret metadata only — no plaintext, ciphertext, or auth tags."
              trailing={<Badge tone="info">{data.secrets.length} records</Badge>}
            />
            <CardContent>
              <DataTable
                columns={secretColumns}
                items={data.secrets}
                empty={<EmptyState icon={KeyRound} title="No secrets stored." body="Store connector or integration credentials here before referencing them from read-only connector workflows." actionLabel="Open Integrations" actionHref="#integrations" />}
                loadError={data.loadErrors.secrets}
                onRetry={onRefresh ? () => void onRefresh() : undefined}
              />
            </CardContent>
          </Card>
        </>
      )}

      {tab === 'privacy' && (
        <Card>
          <CardHeader>
            <CardTitle>Privacy and retention</CardTitle>
            <CardDescription>Updates metadata and evidence retention for this tenant. Shorter windows can purge stored metadata immediately.</CardDescription>
          </CardHeader>
          <CardContent>
            <form className="product-form" onSubmit={handleSaveRetention}>
              <FormNumberField
                label="Metadata retention (days)"
                name="metadata_retention_days"
                min={1}
                max={3650}
                defaultValue={metadataRetentionDays}
                hint="Recommended default: 90 days — events, vault metadata, and notification history."
              />
              <FormNumberField
                label="Report archive (days)"
                name="report_days"
                min={30}
                max={3650}
                defaultValue={getNumber(evidenceRetention, ['report_days'], 365)}
                hint="Recommended default: 365 days — generated readiness report artifacts."
              />
              <FormNumberField
                label="Audit log retention (days)"
                name="audit_log_days"
                min={365}
                max={3650}
                defaultValue={getNumber(evidenceRetention, ['audit_log_days'], 2555)}
                hint="Recommended default: 2555 days (~7 years) — security audit trail."
              />
              <FormNumberField
                label="High-scale artifact retention (days)"
                name="high_scale_artifact_days"
                min={365}
                max={3650}
                defaultValue={getNumber(evidenceRetention, ['high_scale_artifact_days'], 2555)}
                hint="Recommended default: 2555 days — SOC authorization packs and artifacts."
              />
              <label className="check-row full">
                <input name="legal_hold" type="checkbox" defaultChecked={Boolean(evidenceRetention.legal_hold)} />
                <span>Legal hold — block metadata deletions while legal hold is active (read-only boundary for production legal workflows).</span>
              </label>
              <div className="form-actions full">
                <Button type="submit" loading={busy === 'save-retention'} disabled={!tenant}>Save retention policy</Button>
              </div>
            </form>
          </CardContent>
          <CardContent className="settings-list">
            <SettingsNote icon={FileCheck2}>Metadata retention applies to events, evidence vault, reports, and notification events for the current tenant.</SettingsNote>
            <SettingsNote icon={ShieldCheck}>Audit logs, findings, test runs, and authorization artifacts follow separate production retention gates documented in the API reference.</SettingsNote>
          </CardContent>
        </Card>
      )}

      <ConfirmModal
        open={Boolean(pendingRetention)}
        title="Save retention settings?"
        description={<p>Shorter windows can immediately purge stored metadata.</p>}
        confirmLabel="Save retention policy"
        busy={busy === 'save-retention'}
        onCancel={() => setPendingRetention(null)}
        onConfirm={() => void confirmSaveRetention()}
      />
    </div>
  );
}

export function EnvironmentsPage({
  data,
  config,
  session,
  onRefresh
}: {
  data: PortalData;
  config: PortalConfig;
  session: Session;
  onRefresh: () => Promise<void>;
}) {
  const [busy, setBusy] = useState('');
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');
  const [showDeclare, setShowDeclare] = useState(false);
  const rows = buildEnvironmentReadinessRows({
    targetGroups: data.targetGroups,
    runs: data.runs,
    findings: data.findings
  });

  function openDeclare() {
    setError('');
    setMessage('');
    setShowDeclare(true);
  }

  async function handleCreateEnvironment(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const formElement = event.currentTarget;
    const form = new FormData(formElement);
    const name = String(form.get('name') ?? '').trim();
    if (!name) {
      setError('Enter an environment name before declaring.');
      return;
    }
    const description = String(form.get('description') ?? '').trim();
    setBusy('create-environment');
    setError('');
    setMessage('');
    try {
      const result = await requestJson(config, session, '/v1/environments', {
        method: 'POST',
        body: { name, description }
      });
      setMessage(formatMutationSuccessMessage(`Declared environment ${name}.`, result));
      formElement.reset();
      setShowDeclare(false);
      await onRefresh();
    } catch (err) {
      setError(apiErrorMessage(err, 'Could not declare environment.'));
    } finally {
      setBusy('');
    }
  }

  function environmentDisplayName(row: (typeof rows)[number]) {
    const names = row.groups
      .map((group) => getString(group, ['name', 'display_name'], ''))
      .filter((name) => name && name !== '—');
    if (names.length === 0) return '—';
    const unique = [...new Set(names)];
    return unique.length === 1 ? unique[0] : `${unique[0]} (+${unique.length - 1})`;
  }

  function environmentRegion(row: (typeof rows)[number]) {
    for (const group of row.groups) {
      const region = getString(group, ['region', 'region_summary', 'location'], '');
      if (region && region !== '—') return region;
    }
    return '—';
  }

  function environmentAgentCount(environmentId: string) {
    return data.agents.filter((agent) => getString(agent, ['environment_id'], '') === environmentId).length;
  }

  function environmentLastValidation(row: (typeof rows)[number]) {
    const groupIds = new Set(row.groups.map((group) => getString(group, ['id'], '')));
    let latestIso = '';
    for (const run of data.runs) {
      if (!groupIds.has(getString(run, ['target_group_id'], ''))) continue;
      const stamp = run.completed_at ?? run.verdicted_at ?? run.updated_at ?? run.created_at;
      if (stamp === undefined || stamp === null) continue;
      const iso = String(stamp);
      if (!latestIso || iso > latestIso) latestIso = iso;
    }
    return latestIso ? formatDate(latestIso) : '—';
  }

  function environmentStatusTone(row: (typeof rows)[number]) {
    if (row.coverage === 100 && row.openFindings === 0) return 'success' as const;
    if (row.coverage > 0) return 'warn' as const;
    return 'muted' as const;
  }

  function environmentStatusLabel(row: (typeof rows)[number]) {
    if (row.coverage === 100 && row.openFindings === 0) return 'Validated';
    if (row.coverage > 0) return 'Review';
    if (environmentAgentCount(row.id) === 0 && row.groupCount > 0) return 'No agent';
    return 'Needs evidence';
  }

  const environmentColumns: TableColumn<(typeof rows)[number]>[] = [
    { key: 'id', label: 'Environment', render: (row) => <span className="mono">{row.id}</span> },
    { key: 'name', label: 'Name', render: (row) => environmentDisplayName(row) },
    { key: 'region', label: 'Region', render: (row) => <span className="muted">{environmentRegion(row)}</span> },
    { key: 'groups', label: 'Target groups', render: (row) => <span className="tabular-nums">{row.groupCount}</span> },
    { key: 'agents', label: 'Agents', render: (row) => <span className="tabular-nums">{environmentAgentCount(row.id)}</span> },
    {
      key: 'findings',
      label: 'Open findings',
      render: (row) => {
        const open = row.openFindings;
        if (open <= 0) return <Badge tone="success">0</Badge>;
        return <Badge tone={open >= 2 ? 'danger' : 'warn'}>{formatNumber(open)}</Badge>;
      }
    },
    {
      key: 'status',
      label: 'Status',
      render: (row) => <Badge tone={environmentStatusTone(row)}>{environmentStatusLabel(row)}</Badge>
    },
    { key: 'last', label: 'Last validation', render: (row) => <span className="muted">{environmentLastValidation(row)}</span> }
  ];

  return (
    <div className="content">
      <PageHeader
        route="environments"
        actions={
          <Button variant="default" size="sm" disabled={busy !== ''} onClick={openDeclare}>
            Declare environment
          </Button>
        }
      />
      {(message || error) && (
        <div className={error ? 'form-banner error' : 'form-banner neutral'}>{error || message}</div>
      )}
      <Card>
        <CardContent>
          <DataTable
            columns={environmentColumns}
            items={rows}
            getRowId={(row) => row.id}
            getRowProps={(row) => (row.id ? detailRowProps('environment-detail', row.id, `Open environment ${row.id} detail`) : {})}
            empty={
              <EmptyState
                icon={ServerCog}
                title="No environments yet."
                body="Declare an environment below, or create a target group with an environment ID to populate this view."
                actionLabel="Declare environment"
                onAction={openDeclare}
              />
            }
          />
        </CardContent>
      </Card>
      <FormModal
        open={showDeclare}
        title="Declare a new environment"
        description="Declared environments group target scope and validation evidence. No cloud credentials or IP discovery required."
        onClose={() => setShowDeclare(false)}
      >
        {error ? <div className="form-banner error" role="alert">{error}</div> : null}
        <form className="product-form" onSubmit={handleCreateEnvironment}>
          <label>
            <span>Environment name</span>
            <input name="name" placeholder="Production edge" required autoFocus />
          </label>
          <label className="full">
            <span>Description (optional)</span>
            <input name="description" placeholder="What this environment covers" />
          </label>
          <div className="form-actions full">
            <Button type="button" variant="ghost" disabled={busy !== ''} onClick={() => setShowDeclare(false)}>Cancel</Button>
            <Button type="submit" loading={busy === 'create-environment'}>Declare environment</Button>
          </div>
        </form>
      </FormModal>
    </div>
  );
}

export function PolicyPage({
  data,
  config,
  session,
  onRefresh
}: {
  data: PortalData;
  config: PortalConfig;
  session: Session;
  onRefresh: () => Promise<void>;
}) {
  const [busy, setBusy] = useState('');
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');
  const [policyTargetGroupIds, setPolicyTargetGroupIds] = useState<string[]>([]);
  const [policyTargetBindings, setPolicyTargetBindings] = useState<Record<string, PolicyTargetBinding>>({});
  const [policyCheckId, setPolicyCheckId] = useState('');
  const [policyCadence, setPolicyCadence] = useState('weekly');
  const [policyExpectedVerdict, setPolicyExpectedVerdict] = useState('pass');
  const [archivePolicyId, setArchivePolicyId] = useState('');
  const [showCreateSchedule, setShowCreateSchedule] = useState(false);
  const safeChecks = data.checks.filter((check) => getString(check, ['safety_class']) === 'safe');
  const socGatedChecks = data.checks.filter((check) => getString(check, ['safety_class']) === 'soc_gated');
  const checksById = new Map<string, DataItem>(
    data.checks.map((check) => [getString(check, ['check_id', 'id'], ''), check])
  );
  const socScheduledCount = data.testPolicies.filter((policy) => isPolicySocGated(policy, checksById)).length;
  const upcomingRuns = data.testPolicies
    .map((policy) => derivePolicyNextRun(policy, isPolicySocGated(policy, checksById)).iso)
    .filter((iso): iso is string => Boolean(iso))
    .sort((left, right) => left.localeCompare(right));
  const nextRunLabel = upcomingRuns.length > 0 ? formatDate(upcomingRuns[0]) : '—';
  const policyCheckOptions: SelectOption[] = [
    { value: '', label: 'Select check' },
    ...safeChecks.map((check) => ({
      value: getString(check, ['check_id']),
      label: getString(check, ['name', 'check_id'])
    }))
  ];
  const selectedPolicyCheck = safeChecks.find(
    (check) => getString(check, ['check_id', 'id'], '') === policyCheckId
  ) ?? null;
  const activePolicyTargetGroups = data.targetGroups.filter(
    (group) => group.archived_at == null && group.deleted_at == null
  );
  const policyBindingsReady = policyTargetGroupIds.length > 0 && policyTargetGroupIds.every((groupId) => {
    const groupIsActive = activePolicyTargetGroups.some(
      (group) => getString(group, ['id'], '') === groupId
    );
    const binding = policyTargetBindings[groupId];
    return Boolean(
      groupIsActive
      && binding
      && !binding.loading
      && !binding.error
      && binding.selectedTargetId
      && binding.targets.some(
        (target) => getString(target, ['id'], '') === binding.selectedTargetId
          && isPolicyTargetCompatible(selectedPolicyCheck, target)
      )
    );
  });

  useEffect(() => {
    if (!showCreateSchedule) return;
    if (!policyCheckId && safeChecks.length > 0) {
      setPolicyCheckId(getString(safeChecks[0], ['check_id'], ''));
    }
  }, [showCreateSchedule, policyCheckId, safeChecks]);
  function formatPolicySafeWindow(item: DataItem) {
    const windows = item.safe_windows;
    if (!Array.isArray(windows) || windows.length === 0) return '—';
    const first = windows[0];
    if (!first || typeof first !== 'object') return '—';
    const windowItem = first as DataItem;
    const day = getString(windowItem, ['day'], '');
    const start = getString(windowItem, ['start'], '');
    const end = getString(windowItem, ['end'], '');
    if (!start && !end) return '—';
    const range = start && end ? `${start}–${end}` : start || end;
    return day ? `${day} ${range}` : range;
  }

  function policyVerdictBadgeTone(verdict: string): UiBadgeTone {
    const key = verdict.trim().toLowerCase();
    if (['pass', 'passed', 'success', 'ok'].includes(key)) return 'success';
    if (['fail', 'failed', 'gap'].includes(key)) return 'danger';
    if (['review', 'manual_review', 'warn', 'warning', 'partial', 'inconclusive'].includes(key)) return 'warn';
    return 'info';
  }

  const policyColumns: TableColumn<DataItem>[] = [
    { key: 'id', label: 'Schedule', render: (item) => getString(item, ['id', 'policy_id']) },
    {
      key: 'target',
      label: 'Target group',
      render: (item) => {
        const targetGroup = item.target_group && typeof item.target_group === 'object' ? item.target_group as DataItem : {};
        const groupId = getString(item, ['target_group_id'], getString(targetGroup, ['id'], ''));
        const label = getString(targetGroup, ['name', 'id'], groupId);
        return groupId
          ? <AnchorButton size="sm" variant="ghost" href={buildDetailHref('target-group-detail', groupId)}>{label}</AnchorButton>
          : label;
      }
    },
    {
      key: 'check',
      label: 'Check',
      render: (item) => {
        const check = item.check && typeof item.check === 'object' ? item.check as DataItem : {};
        const checkId = getString(item, ['check_id'], getString(check, ['check_id'], ''));
        const label = getString(check, ['name', 'check_id'], checkId);
        return checkId ? <AnchorButton size="sm" variant="ghost" href="#checks">{label}</AnchorButton> : label;
      }
    },
    { key: 'state', label: 'State', render: (item) => {
      const state = getString(item, ['state'], 'active');
      return <Badge tone={state === 'paused' ? 'warn' : 'success'}>{formatPolicyStateLabel(state)}</Badge>;
    } },
    { key: 'cadence', label: 'Cadence', render: (item) => <Badge tone="info">{formatPolicyCadenceLabel(getString(item, ['cadence']))}</Badge> },
    {
      key: 'next_run',
      label: 'Next run',
      render: (item) => {
        const socGated = isPolicySocGated(item, checksById);
        const next = derivePolicyNextRun(item, socGated);
        return socGated ? (
          <Badge tone="warn" title="High-scale schedules run only when SOC schedules them.">Awaiting SOC</Badge>
        ) : (
          <span className="mono muted">{next.label}</span>
        );
      }
    },
    { key: 'safe_window', label: 'Safe window', render: (item) => <span className="mono muted">{formatPolicySafeWindow(item)}</span> },
    { key: 'expected', label: 'Expected verdict', render: (item) => <Badge tone={policyVerdictBadgeTone(getString(item, ['expected_verdict']))}>{formatPolicyVerdictLabel(getString(item, ['expected_verdict']))}</Badge> },
    {
      key: 'exact_target',
      label: 'Exact target',
      render: (item) => {
        const target = item.target && typeof item.target === 'object' ? item.target as DataItem : {};
        const targetId = getString(item, ['target_id'], getString(target, ['id'], ''));
        if (!targetId) return <Badge tone="warn">Unbound legacy schedule</Badge>;
        const targetValue = getString(target, ['value'], targetId);
        const targetKind = getString(target, ['kind'], 'target').replace(/_/g, ' ');
        return (
          <div className="stack-tight">
            <AnchorButton size="sm" variant="ghost" href={buildDetailHref('target-detail', targetId)}>{targetValue}</AnchorButton>
            <span className="mono muted small">{targetKind} · {targetId}</span>
          </div>
        );
      }
    },
    { key: 'updated', label: 'Updated', render: (item) => formatDate(item.updated_at ?? item.created_at) },
    {
      key: 'actions',
      label: 'Actions',
      render: (item) => {
        const id = getString(item, ['id'], '');
        const state = getString(item, ['state'], 'active');
        const rowPatchBusy = busy === `patch-policy-${id}`;
        const rowArchiveBusy = busy === `archive-policy-${id}`;
        const rowBlocked = busy !== '' && !rowPatchBusy && !rowArchiveBusy;
        return (
          <div className="row-actions" aria-busy={rowPatchBusy || rowArchiveBusy || undefined}>
            <Button variant="secondary" loading={rowPatchBusy} disabled={rowBlocked || rowArchiveBusy} onClick={() => void patchPolicy(id, { cadence: 'weekly' }, 'Policy cadence updated to weekly.')}>
              Set weekly cadence
            </Button>
            <Button variant="secondary" loading={rowPatchBusy} disabled={rowBlocked || rowArchiveBusy} onClick={() => void patchPolicy(id, { state: state === 'paused' ? 'active' : 'paused' }, state === 'paused' ? 'Policy resumed.' : 'Policy paused.')}>
              {state === 'paused' ? 'Resume' : 'Pause'}
            </Button>
            <Button variant="danger" loading={rowArchiveBusy} disabled={rowBlocked || rowPatchBusy} onClick={() => setArchivePolicyId(id)}>Archive</Button>
          </div>
        );
      }
    }
  ];

  async function runPolicyAction<T>(label: string, action: () => Promise<T>, success: string) {
    setBusy(label);
    setError('');
    setMessage('');
    try {
      const result = await action();
      setMessage(formatMutationSuccessMessage(success, result));
      await onRefresh();
      return result;
    } catch (err) {
      setError(apiErrorMessage(err, 'Action failed.'));
      return null;
    } finally {
      setBusy('');
    }
  }

  async function loadPolicyTargetsForGroup(targetGroupId: string) {
    setPolicyTargetBindings((current) => ({
      ...current,
      [targetGroupId]: {
        targets: current[targetGroupId]?.targets ?? [],
        selectedTargetId: current[targetGroupId]?.selectedTargetId ?? '',
        loading: true,
        error: ''
      }
    }));
    try {
      const detail = await requestJson(
        config,
        session,
        `/v1/target-groups/${encodeURIComponent(targetGroupId)}`
      ) as DataItem;
      const targets = (Array.isArray(detail.targets) ? detail.targets as DataItem[] : []).filter(
        (target) => target.deleted_at == null && target.archived_at == null
      );
      setPolicyTargetBindings((current) => {
        const selectedTargetId = targets.some(
          (target) => getString(target, ['id'], '') === current[targetGroupId]?.selectedTargetId
            && isPolicyTargetCompatible(selectedPolicyCheck, target)
        ) ? current[targetGroupId]?.selectedTargetId ?? '' : '';
        return {
          ...current,
          [targetGroupId]: { targets, selectedTargetId, loading: false, error: '' }
        };
      });
    } catch (err) {
      setPolicyTargetBindings((current) => ({
        ...current,
        [targetGroupId]: {
          targets: current[targetGroupId]?.targets ?? [],
          selectedTargetId: current[targetGroupId]?.selectedTargetId ?? '',
          loading: false,
          error: apiErrorMessage(err, 'Active targets could not be loaded.')
        }
      }));
    }
  }

  function handlePolicyTargetGroupChange(nextIds: string[]) {
    const newlySelected = nextIds.filter((id) => !policyTargetGroupIds.includes(id));
    setPolicyTargetGroupIds(nextIds);
    for (const targetGroupId of newlySelected) void loadPolicyTargetsForGroup(targetGroupId);
  }

  function handlePolicyCheckChange(nextCheckId: string) {
    const nextCheck = safeChecks.find(
      (check) => getString(check, ['check_id', 'id'], '') === nextCheckId
    ) ?? null;
    setPolicyCheckId(nextCheckId);
    setPolicyTargetBindings((current) => Object.fromEntries(
      Object.entries(current).map(([targetGroupId, binding]) => {
        const selectedTarget = binding.targets.find(
          (target) => getString(target, ['id'], '') === binding.selectedTargetId
        );
        return [
          targetGroupId,
          {
            ...binding,
            selectedTargetId: nextCheck && selectedTarget && isPolicyTargetCompatible(nextCheck, selectedTarget)
              ? binding.selectedTargetId
              : ''
          }
        ];
      })
    ));
  }

  async function handleCreatePolicy(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const formElement = event.currentTarget;
    const form = new FormData(formElement);
    const checkId = String(form.get('check_id') ?? '').trim();
    if (policyTargetGroupIds.length === 0) {
      setError('Select at least one declared target group before creating policies.');
      return;
    }
    if (!policyBindingsReady) {
      setError('Select one exact active target for every selected target group before creating policies.');
      return;
    }
    if (!checkId) {
      setError('Select a check from the catalog before creating a policy.');
      return;
    }

    const cadence = String(form.get('cadence') ?? 'manual').trim();

    const day = String(form.get('safe_window_day') ?? '').trim();
    const start = String(form.get('safe_window_start') ?? '').trim();
    const end = String(form.get('safe_window_end') ?? '').trim();
    const timezone = String(form.get('safe_window_timezone') ?? '').trim();
    const safeWindowValues = [day, start, end, timezone];
    const hasSafeWindow = safeWindowValues.some(Boolean);
    if (hasSafeWindow && !safeWindowValues.every(Boolean)) {
      setError('Complete the safe-window day, start, end, and timezone, or leave all four fields blank.');
      return;
    }
    if (hasSafeWindow && start >= end) {
      setError('Safe window end time must be later than its start time.');
      return;
    }

    const safe_windows = hasSafeWindow ? [{ day, start, end, timezone }] : [];
    const bodyBase = {
      check_id: checkId,
      cadence,
      expected_verdict: String(form.get('expected_verdict') ?? 'pass'),
      safe_windows
    };
    setBusy('create-test-policy');
    setError('');
    setMessage('');
    try {
      const successes: Array<{ targetGroupId: string; targetId: string; result: unknown }> = [];
      const failures: Array<{ targetGroupId: string; targetId: string; message: string }> = [];
      for (const targetGroupId of policyTargetGroupIds) {
        const targetId = policyTargetBindings[targetGroupId]?.selectedTargetId ?? '';
        try {
          const result = await requestJson(config, session, '/v1/test-policies', {
            method: 'POST',
            body: { ...bodyBase, target_group_id: targetGroupId, target_id: targetId }
          });
          successes.push({ targetGroupId, targetId, result });
        } catch (err) {
          failures.push({
            targetGroupId,
            targetId,
            message: apiErrorMessage(err, 'Policy creation failed.')
          });
        }
      }

      let refreshFailure = '';
      if (successes.length > 0) {
        try {
          await onRefresh();
        } catch (err) {
          refreshFailure = apiErrorMessage(err, 'The policy list could not be refreshed.');
        }
      }

      if (failures.length > 0) {
        const failedGroupIds = new Set(failures.map((failure) => failure.targetGroupId));
        setPolicyTargetGroupIds([...failedGroupIds]);
        setPolicyTargetBindings((current) => {
          const retained: Record<string, PolicyTargetBinding> = {};
          for (const [targetGroupId, binding] of Object.entries(current)) {
            if (failedGroupIds.has(targetGroupId)) retained[targetGroupId] = binding;
          }
          return retained;
        });
        const failedResults = failures
          .map((failure) => `${failure.targetGroupId}/${failure.targetId}: ${failure.message}`)
          .join(' ');
        setError(
          `Created ${successes.length} of ${policyTargetGroupIds.length} policies. `
          + `Failed ${failures.length}: ${failedResults} `
          + 'Successful writes were retained; only failed exact target bindings remain selected for retry.'
          + (refreshFailure ? ` ${refreshFailure}` : '')
        );
        return;
      }

      const lastResult = successes.at(-1)?.result ?? null;
      const success = `Created ${successes.length} test ${successes.length === 1 ? 'policy' : 'policies'} from declared scope and check catalog.`;
      if (refreshFailure) {
        setPolicyTargetGroupIds([]);
        setPolicyTargetBindings({});
        formElement.reset();
        setError(`${success} ${refreshFailure} The writes succeeded; refresh the page instead of creating them again.`);
        return;
      }
      setMessage(formatMutationSuccessMessage(success, lastResult));
      setPolicyTargetGroupIds([]);
      setPolicyTargetBindings({});
      formElement.reset();
      setShowCreateSchedule(false);
    } finally {
      setBusy('');
    }
  }

  async function patchPolicy(id: string, body: Record<string, unknown>, success: string) {
    if (!id) return;
    if ('cadence' in body && body.cadence === 'weekly') {
      if (!window.confirm('Set this policy cadence to weekly? Scheduled runs will follow the weekly window.')) return;
    }
    if ('state' in body) {
      const pausing = body.state === 'paused';
      if (!window.confirm(pausing ? 'Pause this policy? Scheduled runs under it will stop.' : 'Resume this policy?')) return;
    }
    await runPolicyAction(`patch-policy-${id}`, () => requestJson(config, session, `/v1/test-policies/${id}`, {
      method: 'PATCH',
      body
    }), success);
  }

  async function archivePolicy(id: string) {
    if (!id) return;
    await runPolicyAction(`archive-policy-${id}`, () => requestJson(config, session, `/v1/test-policies/${id}`, { method: 'DELETE' }), 'Test policy archived.');
    setArchivePolicyId('');
  }

  return (
    <div className="content">
      <PageHeader
        route="test-policies"
        title="Test policies"
        description="Scheduled validation cadences, schedule windows, and target bindings. Each schedule declares when checks run and the verdict they expect. High-scale scenarios stay SOC-scheduled. Click a schedule to open its detail."
        actions={
          <>
            <Button
              variant="default"
              size="sm"
              disabled={busy !== ''}
              onClick={() => setShowCreateSchedule(true)}
            >
              Create schedule
            </Button>
          </>
        }
      />
      <div className="kpi-row">
        <KpiCell
          label="Active schedules"
          value={formatNumber(data.testPolicies.length)}
          delta={`${safeChecks.length} checks bindable`}
        />
        <KpiCell
          label="Next run"
          value={nextRunLabel}
          delta={upcomingRuns.length > 0 ? `${upcomingRuns.length} upcoming` : 'No cadence scheduled'}
        />
        <KpiCell
          label="SOC-scheduled"
          value={formatNumber(socScheduledCount)}
          delta={socScheduledCount > 0 ? 'Awaiting SOC' : 'None gated'}
        />
      </div>
      {(message || error) && (
        <div className={error ? 'form-banner error' : 'form-banner neutral'}>{error || message}</div>
      )}
      <Card className="card--dense">
        <PanelCardHeader
          title="Validation schedules"
          description={
            <>
              Scheduled bindings between declared target groups and customer-runnable checks.
              {' '}
              <span className="muted small">
                {data.testPolicies.length} active · {safeChecks.length} checks · {socGatedChecks.length} SOC-gated
              </span>
            </>
          }
          trailing={data.testPolicies.length > 0 ? <Badge tone="info">{data.testPolicies.length} active</Badge> : undefined}
        />
        <CardContent>
          <DataTable
            columns={policyColumns}
            items={data.testPolicies}
            getRowId={(item) => getString(item, ['id', 'policy_id'], '')}
            getRowProps={(item) => {
              const id = getString(item, ['id', 'policy_id'], '');
              if (!id) return {};
              const rowBusy = busy === `patch-policy-${id}` || busy === `archive-policy-${id}`;
              const linkProps = detailRowProps('policy-detail', id, `Open schedule ${id} detail`);
              return rowBusy ? { ...linkProps, 'aria-busy': true } : linkProps;
            }}
            empty={renderFriendlyEmptyState({
              icon: ClipboardList,
              title: 'No schedules yet.',
              body: 'Create a validation schedule after declaring target groups and reviewing the check catalog.',
              actionLabel: 'New schedule',
              onAction: () => setShowCreateSchedule(true)
            })}
          />
        </CardContent>
      </Card>
      <FormModal
        open={showCreateSchedule}
        title="Create validation schedule"
        description="Bind a customer-runnable check to one exact active target in each selected group. Every target is selected explicitly, each group is written sequentially, and failed bindings remain selected for retry. SOC-gated checks remain request-only."
        wide
        onClose={() => setShowCreateSchedule(false)}
      >
            {(message || error) && showCreateSchedule ? (
              <div className={error ? 'form-banner error' : 'form-banner neutral'}>{error || message}</div>
            ) : null}
            <form className="product-form" onSubmit={(event) => void handleCreatePolicy(event)}>
              <input type="hidden" name="check_id" value={policyCheckId} />
              <input type="hidden" name="cadence" value={policyCadence} />
              <input type="hidden" name="expected_verdict" value={policyExpectedVerdict} />
              <TargetGroupPicker
                groups={activePolicyTargetGroups}
                selectedIds={policyTargetGroupIds}
                onChange={handlePolicyTargetGroupChange}
                disabled={activePolicyTargetGroups.length === 0 || busy !== ''}
              />
              {policyTargetGroupIds.length > 0 ? (
                <div className="full stack-tight" aria-live="polite">
                  <p className="muted small">Choose one exact active target per group. Ambiguous groups are never assigned a target automatically, and the selected identity is immutable after creation.</p>
                  {policyTargetGroupIds.map((targetGroupId) => {
                    const group = activePolicyTargetGroups.find(
                      (candidate) => getString(candidate, ['id'], '') === targetGroupId
                    );
                    const groupName = getString(group ?? {}, ['name'], targetGroupId);
                    const binding = policyTargetBindings[targetGroupId];
                    const targets = binding?.targets ?? [];
                    const compatibleTargets = selectedPolicyCheck
                      ? targets.filter((target) => isPolicyTargetCompatible(selectedPolicyCheck, target))
                      : [];
                    const selectedTarget = compatibleTargets.find(
                      (target) => getString(target, ['id'], '') === binding?.selectedTargetId
                    );
                    const supportedKinds = policySupportedTargetKinds(selectedPolicyCheck);
                    const selectedCheckName = getString(selectedPolicyCheck ?? {}, ['name', 'check_id'], 'selected check');
                    const noCompatibleTargets = Boolean(
                      selectedPolicyCheck && !binding?.loading && !binding?.error && targets.length > 0 && compatibleTargets.length === 0
                    );
                    const targetOptions: SelectOption[] = [
                      {
                        value: '',
                        label: binding?.loading
                          ? 'Loading active targets…'
                          : targets.length === 0
                            ? 'No active targets available'
                            : noCompatibleTargets
                              ? 'No compatible targets'
                              : 'Select exact target'
                      },
                      ...compatibleTargets.map((target) => {
                        const targetId = getString(target, ['id'], '');
                        const kind = effectivePolicyTargetKind(target).replace(/_/g, ' ');
                        return {
                          value: targetId,
                          label: getString(target, ['value'], targetId),
                          description: `${kind} · ${targetId}`
                        };
                      })
                    ];
                    return (
                      <div key={targetGroupId} className="full stack-tight">
                        <Select
                          className="full"
                          label={`${groupName} exact target`}
                          value={binding?.selectedTargetId ?? ''}
                          options={targetOptions}
                          disabled={!selectedPolicyCheck || !binding || binding.loading || Boolean(binding.error) || compatibleTargets.length === 0 || busy !== ''}
                          onChange={(selectedTargetId) => setPolicyTargetBindings((current) => ({
                            ...current,
                            [targetGroupId]: {
                              targets: current[targetGroupId]?.targets ?? [],
                              selectedTargetId,
                              loading: false,
                              error: ''
                            }
                          }))}
                        />
                        {binding?.error ? (
                          <div className="form-banner error" role="alert">
                            {groupName}: {binding.error}
                            {' '}
                            <Button type="button" size="sm" variant="secondary" disabled={busy !== ''} onClick={() => void loadPolicyTargetsForGroup(targetGroupId)}>
                              Retry targets
                            </Button>
                          </div>
                        ) : selectedTarget ? (
                          <p className="muted small">
                            Bound identity: <strong className="mono">{getString(selectedTarget, ['value'], binding.selectedTargetId)}</strong>
                            {' · '}
                            <span className="mono">{binding.selectedTargetId}</span>
                          </p>
                        ) : noCompatibleTargets ? (
                          <p className="form-banner neutral" role="status">
                            {groupName} has no exact target compatible with {selectedCheckName}. This check supports {supportedKinds.join(', ') || 'any declared target kind'}; choose another check or target group.
                          </p>
                        ) : !binding?.loading && targets.length === 0 ? (
                          <p className="form-banner error" role="alert">{groupName} has no active target to schedule.</p>
                        ) : null}
                      </div>
                    );
                  })}
                </div>
              ) : null}
              <Select
                label="Check"
                value={policyCheckId}
                options={policyCheckOptions}
                disabled={safeChecks.length === 0}
                onChange={handlePolicyCheckChange}
              />
              <Select
                label="Cadence"
                value={policyCadence}
                options={POLICY_CADENCE_OPTIONS}
                onChange={setPolicyCadence}
              />
              <Select
                label="Expected verdict"
                value={policyExpectedVerdict}
                options={POLICY_VERDICT_OPTIONS}
                onChange={setPolicyExpectedVerdict}
              />
              <details className="full">
                <summary>Safe window (optional)</summary>
                <p className="muted small full">Leave every field blank for no safe window, or complete all four fields explicitly.</p>
                <label>
                  <span>Safe window day</span>
                  <input name="safe_window_day" placeholder="Mon" autoComplete="off" />
                </label>
                <label>
                  <span>Window timezone</span>
                  <input name="safe_window_timezone" placeholder="UTC" autoComplete="off" spellCheck={false} />
                </label>
                <label>
                  <span>Window start</span>
                  <input name="safe_window_start" type="time" />
                </label>
                <label>
                  <span>Window end</span>
                  <input name="safe_window_end" type="time" />
                </label>
              </details>
              <div className="form-actions full">
                <Button type="button" variant="ghost" disabled={busy !== ''} onClick={() => setShowCreateSchedule(false)}>Cancel</Button>
                <Button
                  type="submit"
                  loading={busy === 'create-test-policy'}
                  disabled={activePolicyTargetGroups.length === 0 || safeChecks.length === 0 || !policyCheckId || !policyBindingsReady || busy !== ''}
                >
                  Create schedule
                </Button>
              </div>
            </form>
      </FormModal>
      <ConfirmModal
        open={Boolean(archivePolicyId)}
        title={`Archive schedule ${archivePolicyId}`}
        description={<p>Are you sure? Scheduled runs under this schedule will stop and an audit entry will be written.</p>}
        confirmLabel="Archive schedule"
        busy={busy === `archive-policy-${archivePolicyId}`}
        onCancel={() => setArchivePolicyId('')}
        onConfirm={() => void archivePolicy(archivePolicyId)}
      />
    </div>
  );
}

const CONNECTOR_SNAPSHOT_KIND_OPTIONS = [
  { value: 'waf_policy', label: 'WAF policy' },
  { value: 'cdn_property', label: 'CDN property' },
  { value: 'dns_zone', label: 'DNS zone' },
  { value: 'cloud_asset', label: 'Cloud asset' },
  { value: 'vulnerability', label: 'Vulnerability' }
] as const;

type DnsProviderDirectoryEntry = {
  id: string;
  label: string;
  icon: LucideIcon;
  backendProvider: 'cloudflare' | 'akamai_edgedns' | 'namecheap' | 'godaddy' | 'ibm_ns1' | 'aws_waf' | 'generic_waf';
  supportsCredentialPolling: boolean;
  capability: string;
  description: string;
  credentialExample?: string;
  tone: 'signal' | 'accent' | 'warn' | 'success';
};

const DNS_PROVIDER_DIRECTORY: readonly DnsProviderDirectoryEntry[] = [
  {
    id: 'cloudflare',
    label: 'Cloudflare',
    icon: CloudSun,
    backendProvider: 'cloudflare',
    supportsCredentialPolling: true,
    capability: 'Read-only zone polling',
    description: 'Poll bounded zone inventory with a vault-backed API token. Successful server-side evidence can verify selected imported domains.',
    credentialExample: 'API token or {"api_token":"..."}',
    tone: 'accent'
  },
  {
    id: 'akamai_edgedns',
    label: 'Akamai EdgeDNS',
    icon: Route,
    backendProvider: 'akamai_edgedns',
    supportsCredentialPolling: true,
    capability: 'Read-only zone polling',
    description: 'Use bounded EdgeGrid-authenticated polling for EdgeDNS zone inventory. No record mutation permission is requested.',
    credentialExample: '{"host":"...luna.akamaiapis.net","access_token":"...","client_token":"...","client_secret":"..."}',
    tone: 'signal'
  },
  {
    id: 'route53',
    label: 'Route 53',
    icon: Route,
    backendProvider: 'generic_waf',
    supportsCredentialPolling: false,
    capability: 'Manual metadata',
    description: 'Record selected DNS-zone metadata without AWS account access or automatic inventory discovery.',
    tone: 'warn'
  },
  {
    id: 'godaddy',
    label: 'GoDaddy',
    icon: Globe2,
    backendProvider: 'godaddy',
    supportsCredentialPolling: true,
    capability: 'Read-only domain polling',
    description: 'List account domains through a bounded, vault-backed API request. Imported domains retain exact provider evidence.',
    credentialExample: '{"key":"...","secret":"..."}',
    tone: 'success'
  },
  {
    id: 'namecheap',
    label: 'Namecheap',
    icon: Globe2,
    backendProvider: 'namecheap',
    supportsCredentialPolling: true,
    capability: 'Read-only domain polling',
    description: 'List domains with a vault credential and an explicitly configured allowlisted egress IP; AstraNull never calls an IP-discovery service.',
    credentialExample: '{"api_username":"...","api_key":"...","client_ip":"203.0.113.10","environment":"production"}',
    tone: 'signal'
  },
  {
    id: 'ibm_ns1',
    label: 'IBM NS1',
    icon: Server,
    backendProvider: 'ibm_ns1',
    supportsCredentialPolling: true,
    capability: 'Read-only zone polling',
    description: 'List NS1 zones with a vault-backed API key through bounded requests to the fixed NS1 API origin.',
    credentialExample: 'API key or {"api_key":"..."}',
    tone: 'accent'
  },
  {
    id: 'hetzner_dns',
    label: 'Hetzner DNS',
    icon: Server,
    backendProvider: 'generic_waf',
    supportsCredentialPolling: false,
    capability: 'Manual metadata',
    description: 'Create a metadata-only provider record and attach operator-supplied DNS-zone evidence.',
    tone: 'accent'
  },
  {
    id: 'google_cloud_dns',
    label: 'Google Cloud DNS',
    icon: Cloud,
    backendProvider: 'generic_waf',
    supportsCredentialPolling: false,
    capability: 'Manual metadata',
    description: 'Record selected cloud DNS metadata without project access or live Cloud DNS polling.',
    tone: 'success'
  },
  {
    id: 'azure_dns',
    label: 'Azure DNS',
    icon: Cloud,
    backendProvider: 'generic_waf',
    supportsCredentialPolling: false,
    capability: 'Manual metadata',
    description: 'Record selected cloud DNS metadata without subscription access or live Azure DNS polling.',
    tone: 'signal'
  },
  {
    id: 'aws',
    label: 'AWS WAF',
    icon: Cloud,
    backendProvider: 'aws_waf',
    supportsCredentialPolling: true,
    capability: 'WAF polling available',
    description: 'Use vault-backed read-only credentials for bounded WAF metadata polling; DNS zones stay manual.',
    tone: 'warn'
  }
];

const DECLARED_DOMAIN_BEHAVIORS = new Set(['block_at_edge', 'absorb_at_origin', 'rate_shape']);

function validateDeclaredHostname(input: string) {
  const hostname = input.trim().toLowerCase().replace(/\.$/, '');
  if (!hostname) return { hostname: '', error: 'Enter a hostname.' };
  if (hostname.length > 253) return { hostname, error: 'Hostname must be 253 characters or fewer.' };
  if (/[\s/:?#@]/.test(hostname)) {
    return { hostname, error: 'Enter a hostname only, without a protocol, port, path, query, or spaces.' };
  }
  const labels = hostname.split('.');
  if (labels.length < 2) return { hostname, error: 'Enter a fully qualified domain name, such as api.example.com.' };
  for (const label of labels) {
    if (!label || label.length > 63) return { hostname, error: 'Each hostname label must contain 1 to 63 characters.' };
    if (!/^[a-z0-9-]+$/.test(label) || label.startsWith('-') || label.endsWith('-')) {
      return { hostname, error: 'Use letters, numbers, and interior hyphens only. International domains must use punycode.' };
    }
  }
  if (/^\d+$/.test(labels[labels.length - 1])) {
    return { hostname, error: 'The final hostname label cannot contain only numbers.' };
  }
  return { hostname, error: '' };
}

const INTEGRATION_PAGE_STYLES = `
.integration-page .dns-provider-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(min(100%, 250px), 1fr));
  gap: var(--space-3);
}
.integration-page .dns-provider-card {
  display: flex;
  min-width: 0;
  min-height: 100%;
  flex-direction: column;
  gap: var(--space-3);
  padding: var(--space-4);
  border: 1px solid var(--border-soft);
  border-radius: var(--radius-lg);
  background: var(--proof-surface);
  transition: border-color var(--motion-fast) var(--motion-ease), background var(--motion-fast) var(--motion-ease), box-shadow var(--motion-fast) var(--motion-ease);
}
.integration-page .dns-provider-card:hover {
  border-color: var(--border-strong);
  background: var(--surface-raised);
  box-shadow: var(--elev-raised);
}
.integration-page .dns-provider-card-head,
.integration-page .dns-provider-card-footer,
.integration-page .dns-directory-heading,
.integration-page .provider-flow-context,
.integration-page .domain-result-heading {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: var(--space-3);
}
.integration-page .dns-provider-identity,
.integration-page .provider-flow-provider {
  display: flex;
  min-width: 0;
  align-items: center;
  gap: var(--space-3);
}
.integration-page .dns-provider-mark {
  display: grid;
  width: var(--space-12);
  height: var(--space-12);
  flex: 0 0 var(--space-12);
  place-items: center;
  border: 1px solid currentColor;
  border-radius: var(--radius-md);
  background: var(--signal-soft);
  color: var(--signal);
}
.integration-page .dns-provider-mark[data-tone='accent'] {
  background: var(--accent-soft);
  color: var(--accent);
}
.integration-page .dns-provider-mark[data-tone='warn'] {
  background: color-mix(in oklab, var(--warn), transparent 88%);
  color: var(--warn);
}
.integration-page .dns-provider-mark[data-tone='success'] {
  background: color-mix(in oklab, var(--success), transparent 88%);
  color: var(--success);
}
.integration-page .dns-provider-name {
  min-width: 0;
}
.integration-page .dns-provider-name strong {
  display: block;
  color: var(--fg);
  font-size: var(--text-sm);
}
.integration-page .dns-provider-name span,
.integration-page .dns-provider-record-count {
  color: var(--muted);
  font-size: var(--text-xs);
}
.integration-page .dns-provider-description {
  min-height: calc(var(--space-12) + var(--space-2));
  margin: 0;
  color: var(--fg-2);
  font-size: var(--text-sm);
  line-height: 1.5;
}
.integration-page .dns-provider-card-footer {
  margin-top: auto;
  padding-top: var(--space-2);
  border-top: 1px solid var(--border-soft);
}
.integration-page .dns-directory-note {
  max-width: 72ch;
  margin: 0;
}
.integration-page .provider-flow-context {
  align-items: flex-end;
  margin-bottom: var(--space-4);
  padding-bottom: var(--space-4);
  border-bottom: 1px solid var(--border-soft);
}
.integration-page .provider-flow-context label {
  min-width: min(100%, 260px);
}
.integration-page .provider-path-grid {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: var(--space-3);
}
.integration-page .provider-path {
  display: flex;
  min-width: 0;
  flex-direction: column;
  align-items: flex-start;
  gap: var(--space-3);
  padding: var(--space-4);
  border: 1px solid var(--border-soft);
  border-radius: var(--radius-lg);
  background: var(--proof-surface);
}
.integration-page .provider-path-icon {
  display: grid;
  width: var(--space-10);
  height: var(--space-10);
  place-items: center;
  border-radius: var(--radius-md);
  background: var(--accent-soft);
  color: var(--accent);
}
.integration-page .provider-path h3,
.integration-page .provider-path p {
  margin: 0;
}
.integration-page .provider-path h3 {
  color: var(--fg);
  font-size: var(--text-sm);
}
.integration-page .provider-path p {
  color: var(--fg-2);
  font-size: var(--text-xs);
  line-height: 1.55;
}
.integration-page .provider-path .btn {
  width: 100%;
  margin-top: auto;
}
.integration-page .domain-scope-options {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: var(--space-2);
}
.integration-page .domain-scope-option {
  display: grid;
  grid-template-columns: auto minmax(0, 1fr);
  align-items: start;
  gap: var(--space-2);
  padding: var(--space-3);
  border: 1px solid var(--border-soft);
  border-radius: var(--radius-md);
  background: var(--proof-surface);
}
.integration-page .domain-scope-option:has(input:checked) {
  border-color: var(--accent);
  background: var(--accent-soft);
}
.integration-page .domain-scope-option input {
  width: auto;
  min-height: 0;
  margin-top: var(--space-1);
}
.integration-page .domain-scope-option strong,
.integration-page .domain-scope-option span {
  display: block;
}
.integration-page .domain-scope-option strong {
  color: var(--fg);
  font-size: var(--text-sm);
}
.integration-page .domain-scope-option span {
  margin-top: var(--space-1);
  color: var(--fg-2);
  font-size: var(--text-xs);
}
.integration-page .domain-progress {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: var(--space-2);
  margin: 0 0 var(--space-3);
  padding: 0;
  list-style: none;
}
.integration-page .domain-progress li {
  display: flex;
  min-width: 0;
  align-items: center;
  gap: var(--space-2);
  color: var(--muted);
  font-size: var(--text-xs);
}
.integration-page .domain-progress li > span {
  display: grid;
  width: var(--space-6);
  height: var(--space-6);
  flex: 0 0 var(--space-6);
  place-items: center;
  border: 1px solid var(--border-strong);
  border-radius: var(--radius-pill);
  background: var(--surface);
  color: var(--fg-2);
  font-family: var(--font-mono);
}
.integration-page .domain-progress li[data-state='active'] > span {
  border-color: var(--accent);
  background: var(--accent-soft);
  color: var(--accent);
}
.integration-page .domain-progress li[data-state='complete'] > span {
  border-color: var(--success);
  background: color-mix(in oklab, var(--success), transparent 88%);
  color: var(--success);
}
.integration-page .domain-progress li[data-state='error'] > span {
  border-color: var(--danger);
  background: color-mix(in oklab, var(--danger), transparent 90%);
  color: var(--danger);
}
.integration-page .domain-progress-status {
  margin: 0 0 var(--space-4);
  color: var(--fg-2);
  font-size: var(--text-sm);
}
.integration-page .domain-provenance,
.integration-page .domain-result {
  padding: var(--space-3);
  border: 1px solid var(--border-soft);
  border-radius: var(--radius-md);
  background: var(--proof-surface);
}
.integration-page .domain-provenance {
  color: var(--fg-2);
  font-size: var(--text-xs);
  line-height: 1.5;
}
.integration-page .domain-result {
  display: flex;
  flex-direction: column;
  gap: var(--space-3);
}
.integration-page .domain-result h3,
.integration-page .domain-result p {
  margin: 0;
}
.integration-page .domain-result h3 {
  color: var(--fg);
  font-size: var(--text-base);
}
.integration-page .domain-result p {
  color: var(--fg-2);
  font-size: var(--text-sm);
}
@media (max-width: 860px) {
  .integration-page .provider-path-grid {
    grid-template-columns: 1fr;
  }
}
@media (max-width: 640px) {
  .integration-page .dns-directory-heading,
  .integration-page .dns-provider-card-footer,
  .integration-page .provider-flow-context,
  .integration-page .domain-result-heading {
    align-items: flex-start;
    flex-direction: column;
  }
  .integration-page .dns-provider-card-footer .btn,
  .integration-page .provider-flow-context label {
    width: 100%;
  }
  .integration-page .domain-scope-options,
  .integration-page .domain-progress {
    grid-template-columns: 1fr;
  }
}
@media (prefers-reduced-motion: reduce) {
  .integration-page .dns-provider-card {
    transition: none;
  }
}
`;

function getDirectoryProvider(id: string) {
  return DNS_PROVIDER_DIRECTORY.find((provider) => provider.id === id) ?? DNS_PROVIDER_DIRECTORY[0];
}

function connectorDirectoryProvider(connector: DataItem) {
  const provider = getString(connector, ['provider'], '').toLowerCase();
  if (provider === 'cloudflare') return getDirectoryProvider('cloudflare');
  if (provider === 'aws_waf') return getDirectoryProvider('aws');
  const direct = DNS_PROVIDER_DIRECTORY.find((entry) => entry.backendProvider === provider && entry.backendProvider !== 'generic_waf');
  if (direct) return direct;
  if (provider !== 'generic_waf') return null;
  const config = getNestedItem(connector, ['config']) ?? getNestedItem(connector, ['config_json']);
  const ownerHint = getString(config ?? {}, ['owner_hint'], '').toLowerCase();
  return DNS_PROVIDER_DIRECTORY.find((entry) => entry.backendProvider === 'generic_waf' && entry.id === ownerHint) ?? null;
}

function formatConnectorProvider(connector: DataItem) {
  const directoryProvider = connectorDirectoryProvider(connector);
  if (directoryProvider) return directoryProvider.label;
  const provider = getString(connector, ['provider'], 'unrecorded');
  return provider.replaceAll('_', ' ');
}

export function IntegrationPage({
  data,
  config,
  session,
  onRefresh
}: {
  data: PortalData;
  config: PortalConfig;
  session: Session;
  onRefresh: () => Promise<void>;
}) {
  const [selectedConnectorId, setSelectedConnectorId] = useState('');
  const [pendingConnector, setPendingConnector] = useState<DataItem | null>(null);
  const [pendingTargetGroup, setPendingTargetGroup] = useState<DataItem | null>(null);
  const [selectedCreateProviderId, setSelectedCreateProviderId] = useState('cloudflare');
  const [connectorSetupMode, setConnectorSetupMode] = useState<'connect' | 'manual'>('connect');
  const [domainTargetGroupId, setDomainTargetGroupId] = useState(() => getString(data.targetGroups[0] ?? {}, ['id'], ''));
  const [domainScopeMode, setDomainScopeMode] = useState<'existing' | 'new'>(data.targetGroups.length > 0 ? 'existing' : 'new');
  const [tenantEnvironments, setTenantEnvironments] = useState<DataItem[]>([]);
  const [selectedEnvironmentId, setSelectedEnvironmentId] = useState('');
  const [environmentsLoading, setEnvironmentsLoading] = useState(true);
  const [environmentError, setEnvironmentError] = useState('');
  const [showConnectorAdvanced, setShowConnectorAdvanced] = useState(false);
  const [showProviderFlow, setShowProviderFlow] = useState(false);
  const [showCreateConnector, setShowCreateConnector] = useState(false);
  const [showManualSnapshot, setShowManualSnapshot] = useState(false);
  const [showAddDomain, setShowAddDomain] = useState(false);
  const [domainProgressStep, setDomainProgressStep] = useState(0);
  const [domainProgressState, setDomainProgressState] = useState<'idle' | 'working' | 'complete' | 'error'>('idle');
  const [domainProgressLabel, setDomainProgressLabel] = useState('');
  const [domainResult, setDomainResult] = useState<{ hostname: string; groupName: string } | null>(null);
  const [snapshots, setSnapshots] = useState<DataItem[]>([]);
  const [busy, setBusy] = useState('');
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');
  const featureFlags = data.deploymentFeatures as { connectors?: boolean; waf_posture?: boolean } | null;
  const connectorsEnabled = featureFlags?.connectors === true;
  const connectorsLoadError = data.loadErrors.connectors;
  const targetGroupsLoadError = data.loadErrors.targetGroups;
  const connectorRecords = pendingConnector && !data.connectors.some(
    (connector) => getString(connector, ['id'], '') === getString(pendingConnector, ['id'], '')
  ) ? [pendingConnector, ...data.connectors] : data.connectors;
  const targetGroupRecords = pendingTargetGroup && !data.targetGroups.some(
    (group) => getString(group, ['id'], '') === getString(pendingTargetGroup, ['id'], '')
  ) ? [pendingTargetGroup, ...data.targetGroups] : data.targetGroups;
  const activeConnectors = connectorRecords.filter(
    (connector) => getString(connector, ['status'], '').toLowerCase() !== 'disabled'
  );
  const selectedConnector =
    activeConnectors.find((connector) => getString(connector, ['id'], '') === selectedConnectorId) ?? activeConnectors[0];
  const effectiveConnectorId = getString(selectedConnector ?? {}, ['id'], '');
  const selectedCreateProvider = getDirectoryProvider(selectedCreateProviderId);
  const effectiveDomainTargetGroupId = targetGroupRecords.some(
    (group) => getString(group, ['id'], '') === domainTargetGroupId
  ) ? domainTargetGroupId : getString(targetGroupRecords[0] ?? {}, ['id'], '');
  const effectiveEnvironmentId = tenantEnvironments.some(
    (environment) => getString(environment, ['id'], '') === selectedEnvironmentId
  ) ? selectedEnvironmentId : getString(tenantEnvironments[0] ?? {}, ['id'], '');
  const domainProgressStages = ['Validate', 'Target group', 'Domain record', 'Refresh'];

  useEffect(() => {
    if (effectiveDomainTargetGroupId !== domainTargetGroupId) {
      setDomainTargetGroupId(effectiveDomainTargetGroupId);
    }
  }, [domainTargetGroupId, effectiveDomainTargetGroupId]);

  useEffect(() => {
    if (effectiveEnvironmentId !== selectedEnvironmentId) {
      setSelectedEnvironmentId(effectiveEnvironmentId);
    }
  }, [effectiveEnvironmentId, selectedEnvironmentId]);

  useEffect(() => {
    let cancelled = false;
    setEnvironmentsLoading(true);
    setEnvironmentError('');
    requestJson(config, session, '/v1/environments')
      .then((response) => {
        const payload = response as { items?: DataItem[] } | DataItem[];
        const items = Array.isArray(payload) ? payload : Array.isArray(payload?.items) ? payload.items : [];
        if (!cancelled) setTenantEnvironments(items);
      })
      .catch((err) => {
        if (!cancelled) {
          setTenantEnvironments([]);
          setEnvironmentError(apiErrorMessage(err, 'Could not load environments.'));
        }
      })
      .finally(() => {
        if (!cancelled) setEnvironmentsLoading(false);
      });
    return () => { cancelled = true; };
  }, [config, session]);

  const connectorColumns: TableColumn<DataItem>[] = [
    { key: 'name', label: 'Connector', render: (item) => getString(item, ['name', 'id']) },
    { key: 'provider', label: 'Provider', render: (item) => <Badge tone="info">{formatConnectorProvider(item)}</Badge> },
    {
      key: 'mode',
      label: 'Capability',
      render: (item) => {
        const provider = getString(item, ['provider'], '').toLowerCase();
        const hasCredentialPoll = ['cloudflare', 'akamai_edgedns', 'namecheap', 'godaddy', 'ibm_ns1', 'aws_waf'].includes(provider) && Boolean(getString(item, ['secret_id'], ''));
        return <Badge tone={hasCredentialPoll ? 'success' : 'muted'}>{hasCredentialPoll ? 'Credential polling' : 'Manual metadata'}</Badge>;
      }
    },
    { key: 'status', label: 'Status', render: (item) => <Badge tone={getString(item, ['status']) === 'active' ? 'success' : getString(item, ['status']) === 'error' ? 'danger' : 'muted'}>{getString(item, ['status'], 'unrecorded')}</Badge> },
    { key: 'last_poll', label: 'Last poll', render: (item) => formatDate(item.last_polled_at ?? item.last_success_at ?? item.last_poll_at) },
    { key: 'poll_errors', label: 'Poll errors', render: (item) => getNumber(item, ['poll_error_count', 'error_count'], 0) },
    { key: 'secret', label: 'Secret ref', render: (item) => getString(item, ['secret_id'], 'none — manual only') },
    { key: 'updated', label: 'Updated', render: (item) => formatDate(item.updated_at ?? item.created_at) },
    {
      key: 'actions',
      label: 'Actions',
      render: (item) => {
        const id = getString(item, ['id'], '');
        const status = getString(item, ['status'], '').toLowerCase();
        const provider = getString(item, ['provider'], '').toLowerCase();
        const isDisabled = status === 'disabled';
        const canPoll = ['cloudflare', 'akamai_edgedns', 'namecheap', 'godaddy', 'ibm_ns1', 'aws_waf'].includes(provider) && Boolean(getString(item, ['secret_id'], ''));
        const rowBusy = busy === `validate-${id}` || busy === `poll-${id}` || busy === `snapshots-${id}` || busy === `disable-${id}`;
        const rowBlocked = busy !== '' && !rowBusy;
        return (
          <div className="row-actions row-actions--compact" aria-busy={rowBusy || undefined}>
            <Button size="sm" variant="secondary" loading={busy === `validate-${id}`} disabled={rowBlocked || isDisabled} onClick={() => void validateConnector(id)}>Validate</Button>
            <Button
              size="sm"
              variant="secondary"
              loading={busy === `poll-${id}`}
              disabled={rowBlocked || isDisabled || !canPoll}
              title={canPoll ? 'Request a bounded read-only provider poll.' : 'Live polling is unavailable; use a manual metadata snapshot.'}
              onClick={() => void pollConnector(id)}
            >
              Poll
            </Button>
            <Button size="sm" variant="ghost" loading={busy === `snapshots-${id}`} disabled={rowBlocked} onClick={() => void loadSnapshots(id)}>Snapshots</Button>
            <Button size="sm" variant="danger" loading={busy === `disable-${id}`} disabled={rowBlocked || isDisabled} onClick={() => void disableConnector(id)}>Disable</Button>
          </div>
        );
      }
    }
  ];

  function openProviderFlow(providerId = 'cloudflare') {
    setSelectedCreateProviderId(providerId);
    setError('');
    setMessage('');
    setShowProviderFlow(true);
  }

  function beginConnectorSetup(mode: 'connect' | 'manual') {
    if (!connectorsEnabled) return;
    if (mode === 'connect' && !selectedCreateProvider.supportsCredentialPolling) return;
    setConnectorSetupMode(mode);
    setShowProviderFlow(false);
    setShowCreateConnector(true);
    setError('');
    setMessage('');
  }

  function openAddDomain() {
    setShowProviderFlow(false);
    setShowAddDomain(true);
    setDomainScopeMode(targetGroupRecords.length > 0 ? 'existing' : 'new');
    setDomainProgressStep(0);
    setDomainProgressState('idle');
    setDomainProgressLabel('');
    setDomainResult(null);
    setError('');
    setMessage('');
  }

  function closeAddDomain() {
    if (busy === 'add-single-domain') return;
    setShowAddDomain(false);
    setDomainResult(null);
    setDomainProgressState('idle');
    setError('');
  }

  async function retryEnvironmentLoad() {
    setEnvironmentsLoading(true);
    setEnvironmentError('');
    try {
      const response = await requestJson(config, session, '/v1/environments') as { items?: DataItem[] } | DataItem[];
      setTenantEnvironments(Array.isArray(response) ? response : Array.isArray(response?.items) ? response.items : []);
    } catch (err) {
      setTenantEnvironments([]);
      setEnvironmentError(apiErrorMessage(err, 'Could not load environments.'));
    } finally {
      setEnvironmentsLoading(false);
    }
  }

  function setDomainValidationError(nextError: string) {
    setError(nextError);
    setMessage('');
    setDomainProgressStep(1);
    setDomainProgressState('error');
    setDomainProgressLabel(nextError);
  }

  async function runAction<T>(label: string, action: () => Promise<T>, success: string) {
    setBusy(label);
    setError('');
    setMessage('');
    try {
      const result = await action();
      setMessage(formatMutationSuccessMessage(success, result));
      await onRefresh();
      return result;
    } catch (err) {
      setError(apiErrorMessage(err, 'Action failed.'));
      return null;
    } finally {
      setBusy('');
    }
  }

  async function handleAddSingleDomain(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const formElement = event.currentTarget;
    const form = new FormData(formElement);
    const hostnameResult = validateDeclaredHostname(String(form.get('hostname') ?? ''));
    const expectedBehavior = String(form.get('expected_behavior') ?? '').trim();
    const groupName = String(form.get('group_name') ?? '').trim();
    const selectedGroup = targetGroupRecords.find((group) => getString(group, ['id'], '') === effectiveDomainTargetGroupId) ?? null;

    if (hostnameResult.error) {
      setDomainValidationError(hostnameResult.error);
      return;
    }
    if (!DECLARED_DOMAIN_BEHAVIORS.has(expectedBehavior)) {
      setDomainValidationError('Select a supported expected behavior for this domain.');
      return;
    }
    if (domainScopeMode === 'existing' && !effectiveDomainTargetGroupId) {
      setDomainValidationError(targetGroupsLoadError
        ? 'Target groups could not be loaded. Retry the list or create a new declared group.'
        : 'Select a target group or choose Create new group.');
      return;
    }
    if (domainScopeMode === 'new') {
      if (!groupName) {
        setDomainValidationError('Enter a name for the new target group.');
        return;
      }
      if (groupName.length > 120) {
        setDomainValidationError('Target group name must be 120 characters or fewer.');
        return;
      }
      if (environmentsLoading) {
        setDomainValidationError('Wait for environments to finish loading before creating the group.');
        return;
      }
      if (environmentError) {
        setDomainValidationError('Environments could not be loaded. Retry before creating the group.');
        return;
      }
      if (!effectiveEnvironmentId) {
        setDomainValidationError('Create an environment before creating a target group.');
        return;
      }
    }

    setBusy('add-single-domain');
    setError('');
    setMessage('');
    setDomainResult(null);
    setDomainProgressState('working');
    setDomainProgressStep(1);
    setDomainProgressLabel(`Validated ${hostnameResult.hostname}.`);

    let groupId = effectiveDomainTargetGroupId;
    let resolvedGroupName = getString(selectedGroup ?? {}, ['name'], groupId);
    let createdGroup: DataItem | null = null;
    try {
      setDomainProgressStep(2);
      if (domainScopeMode === 'new') {
        setDomainProgressLabel(`Creating declared target group “${groupName}”…`);
        createdGroup = await requestJson(config, session, '/v1/target-groups', {
          method: 'POST',
          body: {
            name: groupName,
            environment_id: effectiveEnvironmentId,
            description: 'Customer-created from the Integrations single-domain declaration flow.',
            expected_behavior_default: expectedBehavior,
            validation_mode: 'external_only',
            timezone: 'UTC'
          }
        }) as DataItem;
        groupId = getString(createdGroup, ['id'], '');
        if (!groupId) throw new Error('The target group was created without a usable identifier. Refresh and verify the group before retrying.');
        resolvedGroupName = getString(createdGroup, ['name'], groupName);
        setPendingTargetGroup(createdGroup);
        setDomainTargetGroupId(groupId);
      } else {
        setDomainProgressLabel(`Using declared target group “${resolvedGroupName}”.`);
      }

      setDomainProgressStep(3);
      setDomainProgressLabel(`Adding ${hostnameResult.hostname} as a customer-declared FQDN…`);
      await requestJson(config, session, `/v1/target-groups/${encodeURIComponent(groupId)}/targets`, {
        method: 'POST',
        body: {
          kind: 'fqdn',
          value: hostnameResult.hostname,
          expected_behavior: expectedBehavior,
          metadata: {
            source: 'manual',
            source_app: 'AstraNull portal',
            declaration_path: 'integrations_single_domain',
            provider_access: 'none'
          }
        }
      });

      setDomainProgressStep(4);
      setDomainProgressLabel('Refreshing declared inventory…');
      try {
        await onRefresh();
      } catch {
        // The write is already complete. Keep the success truthful and let the user refresh later.
      }
      const success = `${hostnameResult.hostname} was added to ${resolvedGroupName}. No provider credentials or inventory discovery were used. Ownership remains unverified.`;
      setMessage(success);
      setDomainResult({ hostname: hostnameResult.hostname, groupName: resolvedGroupName });
      setDomainProgressState('complete');
      setDomainProgressLabel('Domain declaration complete. Verify ownership before running external probes.');
      formElement.reset();
    } catch (err) {
      const failure = apiErrorMessage(err, 'Could not add the declared domain.');
      if (createdGroup && groupId) {
        setPendingTargetGroup(createdGroup);
        setDomainTargetGroupId(groupId);
        setDomainScopeMode('existing');
        try { await onRefresh(); } catch { /* Preserve the actionable write error below. */ }
        setError(`Target group “${resolvedGroupName}” was created, but ${hostnameResult.hostname} was not added. ${failure} The form now targets the created group; retry to add only the domain.`);
      } else {
        setError(failure);
      }
      setDomainProgressState('error');
      setDomainProgressLabel(failure);
    } finally {
      setBusy('');
    }
  }

  async function handleCreateConnector(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const formElement = event.currentTarget;
    const form = new FormData(formElement);
    const directoryProvider = getDirectoryProvider(String(form.get('provider') ?? selectedCreateProviderId));
    const credentialSetup = connectorSetupMode === 'connect';
    if (credentialSetup && !directoryProvider.supportsCredentialPolling) {
      setError(`${directoryProvider.label} does not have an implemented credential polling path. Choose Manual metadata instead.`);
      return;
    }
    const provider = directoryProvider.backendProvider;
    const name = String(form.get('name') ?? '').trim();
    const secretInput = credentialSetup ? String(form.get('secret') ?? '').trim() : '';
    const externalSecretId = credentialSetup ? String(form.get('secret_id') ?? '').trim() : '';
    const resourceRefHash = String(form.get('resource_ref_hash') ?? '').trim();
    const region = String(form.get('region') ?? '').trim();
    const defaultSnapshotKind = String(form.get('default_snapshot_kind') ?? (provider === 'aws_waf' ? 'waf_policy' : 'dns_zone'));
    if (!name) {
      setError('Connector name is required.');
      return;
    }
    if (credentialSetup && !secretInput && !externalSecretId) {
      setError('Enter a read-only credential or an existing vault secret reference to enable polling.');
      return;
    }
    if (secretInput && externalSecretId) {
      setError('Choose either a new credential or an existing secret reference, not both.');
      return;
    }
    if (secretInput && !window.confirm('Store this read-only provider credential in the encrypted tenant vault before creating the connector?')) return;

    const createdResult = await runAction('create-connector', async () => {
      let secretId = externalSecretId || null;
      if (secretInput) {
        const stored = await requestJson(config, session, '/v1/secrets', {
          method: 'POST',
          body: {
            purpose: 'waf_connector',
            name: `${provider}:${name}`,
            plaintext: secretInput,
            metadata: { provider, read_only: true, access: 'bounded_metadata_polling' }
          }
        }) as { secret?: { id?: string } };
        secretId = stored.secret?.id ?? null;
      }
      const created = await requestJson(config, session, '/v1/connectors', {
        method: 'POST',
        body: {
          provider,
          name,
          ...(secretId ? { secret_id: secretId } : {}),
          status: 'active',
          config: {
            read_only: true,
            connection_mode: credentialSetup ? 'bounded_polling' : 'manual_metadata',
            default_snapshot_kind: defaultSnapshotKind,
            ...(provider === 'generic_waf' ? { owner_hint: directoryProvider.id } : {}),
            ...(provider === 'cloudflare' && resourceRefHash ? { zone_ref_hash: resourceRefHash } : {}),
            ...(provider !== 'cloudflare' && resourceRefHash ? { resource_ref_hash: resourceRefHash } : {}),
            ...(provider === 'aws_waf' && region ? { region_summary: region } : {})
          }
        }
      }) as { connector?: DataItem };
      if (created.connector?.id) {
        setPendingConnector(created.connector);
        setSelectedConnectorId(String(created.connector.id));
      }
      formElement.reset();
      setShowCreateConnector(false);
      return created;
    }, credentialSetup
      ? 'Read-only connector created. Validate it before requesting a provider poll.'
      : 'Manual metadata connector created without provider credentials.');

    if (createdResult && connectorSetupMode === 'manual') {
      setShowManualSnapshot(true);
      setMessage('Manual metadata connector created. Add its first normalized snapshot now; no provider access is used.');
    }
  }

  async function validateConnector(id: string) {
    if (!id) return;
    await runAction(`validate-${id}`, () => requestJson(config, session, `/v1/connectors/${encodeURIComponent(id)}/validate`, { method: 'POST' }), 'Connector validation completed.');
  }

  async function pollConnector(id: string) {
    if (!id) return;
    const result = await runAction(`poll-${id}`, () => requestJson(config, session, `/v1/connectors/${encodeURIComponent(id)}/poll`, { method: 'POST', body: {} }), 'Connector poll requested.');
    const nextSnapshots = result && typeof result === 'object' && 'snapshots' in result ? (result as { snapshots?: DataItem[] }).snapshots : null;
    if (Array.isArray(nextSnapshots)) setSnapshots(nextSnapshots);
  }

  async function disableConnector(id: string) {
    if (!id) return;
    if (!window.confirm('Disable this connector? Deliveries through it will stop.')) return;
    await runAction(`disable-${id}`, () => requestJson(config, session, `/v1/connectors/${encodeURIComponent(id)}/disable`, { method: 'POST', body: { reason: 'Disabled from integrations page.' } }), 'Connector disabled.');
  }

  async function loadSnapshots(id: string) {
    if (!id) return;
    const result = await runAction(`snapshots-${id}`, () => requestJson(config, session, `/v1/connectors/${encodeURIComponent(id)}/snapshots`), 'Connector snapshots loaded.');
    const items = result && typeof result === 'object' && 'items' in result ? (result as { items?: DataItem[] }).items : null;
    setSnapshots(Array.isArray(items) ? items : []);
    setSelectedConnectorId(id);
  }

  async function handleManualSnapshot(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const formElement = event.currentTarget;
    const id = effectiveConnectorId;
    if (!id) {
      setError('Create or select a connector before adding a snapshot.');
      return;
    }
    const form = new FormData(formElement);
    const hostnames = String(form.get('hostnames') ?? '')
      .split(',')
      .map((value) => value.trim())
      .filter(Boolean);
    const ruleCount = Number(form.get('rule_count') ?? 0);
    const snapshot = {
      snapshot_kind: String(form.get('snapshot_kind') ?? 'waf_policy'),
      display_ref: String(form.get('display_ref') ?? '').trim(),
      resource_ref_hash: String(form.get('resource_ref_hash') ?? '').trim(),
      config_hash: String(form.get('config_hash') ?? '').trim(),
      summary: {
        policy_mode: String(form.get('policy_mode') ?? 'monitor'),
        rule_count: Number.isFinite(ruleCount) ? ruleCount : 0,
        ...(hostnames.length ? { hostnames } : {})
      }
    };
    if (!snapshot.display_ref || !snapshot.resource_ref_hash || !snapshot.config_hash) {
      setError('Display ref, resource hash, and config hash are required for a metadata snapshot.');
      return;
    }
    const result = await runAction(
      `snapshot-${id}`,
      () => requestJson(config, session, `/v1/connectors/${encodeURIComponent(id)}/poll`, { method: 'POST', body: { manual_only: true, snapshots: [snapshot] } }),
      'Manual connector snapshot ingested.'
    );
    const nextSnapshots = result && typeof result === 'object' && 'snapshots' in result ? (result as { snapshots?: DataItem[] }).snapshots : null;
    if (Array.isArray(nextSnapshots)) setSnapshots(nextSnapshots);
    if (result) {
      formElement.reset();
      setShowManualSnapshot(false);
    }
  }

  function domainStageState(index: number) {
    const step = index + 1;
    if (domainProgressState === 'complete' || step < domainProgressStep) return 'complete';
    if (step === domainProgressStep && domainProgressState === 'error') return 'error';
    if (step === domainProgressStep && domainProgressState === 'working') return 'active';
    return 'pending';
  }

  return (
    <div className="content integration-page">
      <style>{INTEGRATION_PAGE_STYLES}</style>
      <PageHeader
        route="integrations"
        eyebrow="DNS & edge integrations"
        actions={
          <>
            <Button variant="default" size="sm" disabled={busy !== ''} onClick={() => openProviderFlow()}><PlugZap size={15} aria-hidden="true" /> Add provider</Button>
            {connectorsEnabled ? (
              <Button
                variant="secondary"
                size="sm"
                disabled={activeConnectors.length === 0 || busy !== '' || Boolean(connectorsLoadError)}
                onClick={() => {
                  setError('');
                  setMessage('');
                  setShowManualSnapshot(true);
                }}
              >
                <FileCheck2 size={15} aria-hidden="true" /> Manual snapshot
              </Button>
            ) : null}
          </>
        }
      />
      <PageContextSummary>
        <span className="tabular-nums">{DNS_PROVIDER_DIRECTORY.length}</span> provider paths ·{' '}
        {connectorsLoadError ? 'connector status unavailable' : <><span className="tabular-nums">{connectorRecords.length}</span> connector records</>} · provider access remains optional
      </PageContextSummary>
      {(message || error) && (
        <div
          className={error ? 'form-banner error' : 'form-banner'}
          role={error ? 'alert' : 'status'}
          aria-live="polite"
        >
          {error || message}
        </div>
      )}

      <Card>
        <CardHeader>
          <div className="dns-directory-heading">
            <div>
              <CardTitle id="dns-provider-directory-title">DNS provider directory</CardTitle>
              <CardDescription className="dns-directory-note">
                Choose an implemented read-only connector, a manual metadata record, or one customer-declared domain. Opening a provider never grants AstraNull cloud access.
              </CardDescription>
            </div>
            <Badge tone="info">Optional integrations</Badge>
          </div>
        </CardHeader>
        <CardContent>
          <div className="dns-provider-grid" aria-labelledby="dns-provider-directory-title">
            {DNS_PROVIDER_DIRECTORY.map((provider) => {
              const ProviderIcon = provider.icon;
              const configuredCount = connectorsLoadError ? null : connectorRecords.filter(
                (connector) => connectorDirectoryProvider(connector)?.id === provider.id
              ).length;
              return (
                <article className="dns-provider-card" key={provider.id}>
                  <div className="dns-provider-card-head">
                    <div className="dns-provider-identity">
                      <div className="dns-provider-mark" data-tone={provider.tone} aria-hidden="true">
                        <ProviderIcon size={20} strokeWidth={1.8} />
                      </div>
                      <div className="dns-provider-name">
                        <strong>{provider.label}</strong>
                        <span>DNS / edge metadata</span>
                      </div>
                    </div>
                    <Badge tone={provider.supportsCredentialPolling ? 'info' : 'muted'}>{provider.capability}</Badge>
                  </div>
                  <p className="dns-provider-description">{provider.description}</p>
                  <div className="dns-provider-card-footer">
                    <span className="dns-provider-record-count tabular-nums">
                      {configuredCount === null ? 'Status unavailable' : configuredCount > 0 ? `${configuredCount} configured` : 'Not configured'}
                    </span>
                    <Button size="sm" variant="secondary" onClick={() => openProviderFlow(provider.id)}>
                      Add
                    </Button>
                  </div>
                </article>
              );
            })}
          </div>
        </CardContent>
      </Card>

      {!connectorsEnabled ? (
        <Card>
          <CardHeader>
            <CardTitle>Connector add-on is disabled</CardTitle>
            <CardDescription>Provider connector records and snapshots are not enabled for this tenant.</CardDescription>
          </CardHeader>
          <CardContent className="callout-list">
            <CalloutNote icon={ShieldCheck} tone="info">Core DDoS validation and the single-domain flow continue to work without cloud credentials.</CalloutNote>
            <CalloutNote icon={FileCheck2}>Contact support only if you need optional read-only connector metadata.</CalloutNote>
          </CardContent>
        </Card>
      ) : (
        <>
          <Card className="card--dense">
            <PanelCardHeader
              title="Configured connectors"
              description="Validate connector metadata, run supported credential-backed polls, load snapshots, or disable a record. Plaintext credentials are never rendered."
              trailing={<Badge tone={connectorsLoadError ? 'warn' : 'info'}>{connectorsLoadError ? 'Unavailable' : `${connectorRecords.length} total`}</Badge>}
            />
            <CardContent>
              <DataTable
                columns={connectorColumns}
                items={connectorRecords}
                loadError={connectorsLoadError}
                onRetry={() => void onRefresh()}
                empty={<EmptyState icon={PlugZap} title="No connectors configured." body="Configure an optional read-only provider record, or keep using declared domains and manual evidence without provider access." />}
              />
            </CardContent>
          </Card>
          {snapshots.length > 0 ? (
            <Card className="card--dense">
              <PanelCardHeader
                title="Loaded connector snapshots"
                description="Returned by a supported provider poll or manual metadata ingest."
                trailing={<Badge tone="muted">{snapshots.length}</Badge>}
              />
              <CardContent className="support-evidence-list">
                {snapshots.map((snapshot) => (
                  <div key={getString(snapshot, ['id'])} className="support-evidence-item">
                    <div className="support-evidence-main">
                      <span className="support-evidence-type">{getString(snapshot, ['snapshot_kind'])}</span>
                      <span className="support-evidence-action">{getString(snapshot, ['display_ref'])}</span>
                    </div>
                    <span className="muted">{formatDate(snapshot.observed_at ?? snapshot.created_at)}</span>
                  </div>
                ))}
              </CardContent>
            </Card>
          ) : null}
        </>
      )}

      <FormModal
        open={showProviderFlow}
        title="Add provider"
        description="Choose the least-access path that meets your need. A provider selection alone never connects an account."
        wide
        onClose={() => setShowProviderFlow(false)}
      >
        <div className="provider-flow-context">
          <div className="provider-flow-provider">
            <div className="dns-provider-mark" data-tone={selectedCreateProvider.tone} aria-hidden="true">
              <selectedCreateProvider.icon size={20} strokeWidth={1.8} />
            </div>
            <div className="dns-provider-name">
              <strong>{selectedCreateProvider.label}</strong>
              <span>{selectedCreateProvider.capability}</span>
            </div>
          </div>
          <label>
            <span>Provider</span>
            <select value={selectedCreateProviderId} onChange={(event) => setSelectedCreateProviderId(event.target.value)}>
              {DNS_PROVIDER_DIRECTORY.map((provider) => <option key={provider.id} value={provider.id}>{provider.label}</option>)}
            </select>
          </label>
        </div>
        <div className="provider-path-grid">
          <article className="provider-path">
            <span className="provider-path-icon" aria-hidden="true"><KeyRound size={18} /></span>
            <Badge tone={connectorsEnabled && selectedCreateProvider.supportsCredentialPolling ? 'success' : 'muted'}>
              {connectorsEnabled && selectedCreateProvider.supportsCredentialPolling ? 'Implemented' : 'Unavailable for this provider'}
            </Badge>
            <h3>Connect read-only</h3>
            <p>Store a vault-backed read-only credential and use the bounded polling worker for Cloudflare, Akamai EdgeDNS, Namecheap, GoDaddy, IBM NS1, or AWS WAF.</p>
            <Button
              type="button"
              size="sm"
              disabled={!connectorsEnabled || !selectedCreateProvider.supportsCredentialPolling}
              onClick={() => beginConnectorSetup('connect')}
            >
              Continue to connect
            </Button>
          </article>
          <article className="provider-path">
            <span className="provider-path-icon" aria-hidden="true"><FileCheck2 size={18} /></span>
            <Badge tone={connectorsEnabled ? 'info' : 'muted'}>{connectorsEnabled ? 'No credentials' : 'Add-on disabled'}</Badge>
            <h3>Manual metadata</h3>
            <p>Create a provider record without credentials, then submit selected normalized zone or policy metadata. No provider API call is made.</p>
            <Button type="button" size="sm" variant="secondary" disabled={!connectorsEnabled} onClick={() => beginConnectorSetup('manual')}>
              Continue manually
            </Button>
          </article>
          <article className="provider-path">
            <span className="provider-path-icon" aria-hidden="true"><Target size={18} /></span>
            <Badge tone="info">Core workflow</Badge>
            <h3>Single domain</h3>
            <p>Declare one FQDN in an existing or new target group. This creates scoped inventory only; ownership verification remains required.</p>
            <Button type="button" size="sm" variant="secondary" onClick={openAddDomain}>
              + Add single domain
            </Button>
          </article>
        </div>
        <div className="form-actions">
          <Button type="button" variant="ghost" onClick={() => setShowProviderFlow(false)}>Cancel</Button>
        </div>
      </FormModal>

      {connectorsEnabled ? (
        <>
          <FormModal
            open={showCreateConnector}
            title={connectorSetupMode === 'connect' ? `Connect ${selectedCreateProvider.label} read-only` : `Add ${selectedCreateProvider.label} manually`}
            description={connectorSetupMode === 'connect'
              ? 'Creates a vault-backed connector for the implemented bounded metadata poller. Validate it before the first poll.'
              : 'Creates a metadata-only connector. No cloud credential or provider API access is requested.'}
            wide
            onClose={() => setShowCreateConnector(false)}
          >
            {error ? <div className="form-banner error" role="alert">{error}</div> : null}
            <form className="product-form" onSubmit={handleCreateConnector} aria-busy={busy === 'create-connector' || undefined}>
              <fieldset disabled={busy !== ''}>
                <label>
                  <span>Provider</span>
                  <select
                    name="provider"
                    value={selectedCreateProviderId}
                    onChange={(event) => setSelectedCreateProviderId(event.target.value)}
                  >
                    {DNS_PROVIDER_DIRECTORY.filter((provider) => connectorSetupMode === 'manual' || provider.supportsCredentialPolling).map((provider) => (
                      <option key={provider.id} value={provider.id}>
                        {provider.label} — {provider.supportsCredentialPolling ? provider.capability : 'manual metadata'}
                      </option>
                    ))}
                  </select>
                </label>
                <label>
                  <span>Connector name</span>
                  <input name="name" placeholder={`${selectedCreateProvider.id}-${connectorSetupMode === 'connect' ? 'readonly' : 'manual'}`} required />
                </label>
                {connectorSetupMode === 'connect' ? (
                  <>
                    <label className="full">
                      <span>New read-only credential</span>
                      <textarea
                        name="secret"
                        rows={4}
                        placeholder={selectedCreateProvider.credentialExample ?? (selectedCreateProvider.backendProvider === 'aws_waf'
                          ? 'Read-only AWS credential JSON'
                          : 'Read-only provider credential JSON')}
                      />
                    </label>
                    <label className="full">
                      <span>Or existing vault secret ref</span>
                      <input name="secret_id" placeholder="secret_..." />
                    </label>
                    <p className="muted full">Provide one option. New credentials are encrypted in the tenant vault and never shown again.</p>
                  </>
                ) : (
                  <div className="full">
                    <CalloutNote icon={FileCheck2} tone="info">
                      Manual mode never accepts provider credentials. After creation, add a normalized metadata snapshot with hashes rather than raw provider payloads.
                    </CalloutNote>
                  </div>
                )}
                <details className="full" open={showConnectorAdvanced} onToggle={(event) => setShowConnectorAdvanced((event.currentTarget as HTMLDetailsElement).open)}>
                  <summary>Advanced metadata</summary>
                  <label>
                    <span>Resource hash</span>
                    <input name="resource_ref_hash" placeholder="Optional zone or resource hash" />
                  </label>
                  {selectedCreateProvider.backendProvider === 'aws_waf' ? (
                    <label>
                      <span>AWS region</span>
                      <input name="region" placeholder="us-east-1" />
                    </label>
                  ) : null}
                  <label>
                    <span>Default snapshot kind</span>
                    <select name="default_snapshot_kind" defaultValue={selectedCreateProvider.backendProvider === 'aws_waf' ? 'waf_policy' : 'dns_zone'}>
                      {CONNECTOR_SNAPSHOT_KIND_OPTIONS.map((option) => (
                        <option key={option.value} value={option.value}>{option.label}</option>
                      ))}
                    </select>
                  </label>
                </details>
                <div className="form-actions full">
                  <Button type="button" variant="ghost" disabled={busy !== ''} onClick={() => setShowCreateConnector(false)}>Cancel</Button>
                  <Button loading={busy === 'create-connector'} disabled={busy !== ''} type="submit">
                    {connectorSetupMode === 'connect' ? 'Create read-only connector' : 'Create manual connector'}
                  </Button>
                </div>
              </fieldset>
            </form>
          </FormModal>

          <FormModal
            open={showManualSnapshot}
            title="Manual metadata snapshot"
            description="Use this for generic providers, or whenever credential-backed polling is unavailable. Only normalized metadata is accepted."
            wide
            onClose={() => setShowManualSnapshot(false)}
          >
            {error ? <div className="form-banner error" role="alert">{error}</div> : null}
            {connectorsLoadError && !pendingConnector ? (
              <div className="form-banner error" role="alert">
                <span>Could not load connectors — {connectorsLoadError}</span>
                <Button type="button" size="sm" variant="ghost" onClick={() => void onRefresh()}>Retry</Button>
              </div>
            ) : (
              <form className="product-form" onSubmit={handleManualSnapshot} aria-busy={busy.startsWith('snapshot-') || undefined}>
                <label className="full">
                  <span>Connector</span>
                  <select value={effectiveConnectorId} onChange={(event) => setSelectedConnectorId(event.target.value)} required>
                    {activeConnectors.map((connector) => (
                      <option key={getString(connector, ['id'])} value={getString(connector, ['id'])}>
                        {getString(connector, ['name'])} — {formatConnectorProvider(connector)}
                      </option>
                    ))}
                  </select>
                </label>
                <label>
                  <span>Snapshot kind</span>
                  <select name="snapshot_kind" defaultValue="dns_zone">
                    {CONNECTOR_SNAPSHOT_KIND_OPTIONS.map((option) => (
                      <option key={option.value} value={option.value}>{option.label}</option>
                    ))}
                  </select>
                </label>
                <label>
                  <span>Display ref</span>
                  <input name="display_ref" placeholder="zone-a" required />
                </label>
                <label>
                  <span>Resource hash</span>
                  <input name="resource_ref_hash" placeholder="res_hash_1" required />
                </label>
                <label>
                  <span>Config hash</span>
                  <input name="config_hash" placeholder="cfg_hash_1" required />
                </label>
                <label>
                  <span>Policy mode</span>
                  <select name="policy_mode" defaultValue="monitor">
                    <option value="block">Block</option>
                    <option value="monitor">Monitor</option>
                    <option value="unknown">Unknown</option>
                  </select>
                </label>
                <label>
                  <span>Rule count</span>
                  <input name="rule_count" type="number" min="0" defaultValue="0" />
                </label>
                <label className="full">
                  <span>Hostnames</span>
                  <input name="hostnames" placeholder="app.example.com, api.example.com" />
                </label>
                <div className="form-actions full">
                  <Button type="button" variant="ghost" disabled={busy !== ''} onClick={() => setShowManualSnapshot(false)}>Cancel</Button>
                  <Button loading={busy.startsWith('snapshot-')} disabled={busy !== '' || !effectiveConnectorId} type="submit">Ingest snapshot</Button>
                </div>
              </form>
            )}
          </FormModal>
        </>
      ) : null}

      <FormModal
        open={showAddDomain}
        title="Add single domain"
        description="Declare one hostname in an existing or new customer target group. This is not provider discovery and does not grant cloud access."
        wide
        onClose={closeAddDomain}
      >
        {error ? <div className="form-banner error" role="alert">{error}</div> : null}
        {domainProgressState !== 'idle' ? (
          <>
            <ol className="domain-progress" aria-label="Domain declaration progress">
              {domainProgressStages.map((stage, index) => {
                const state = domainStageState(index);
                return (
                  <li key={stage} data-state={state}>
                    <span aria-hidden="true">{state === 'complete' ? <CheckCircle2 size={14} /> : index + 1}</span>
                    <small>{stage}</small>
                  </li>
                );
              })}
            </ol>
            <p className="domain-progress-status" role={domainProgressState === 'error' ? 'alert' : 'status'} aria-live="polite">{domainProgressLabel}</p>
          </>
        ) : null}
        {domainResult ? (
          <div className="domain-result">
            <div className="domain-result-heading">
              <div>
                <h3>{domainResult.hostname} is now declared</h3>
                <p>Target group: {domainResult.groupName}</p>
              </div>
              <Badge tone="warn">Ownership unverified</Badge>
            </div>
            <p>Provenance: manual customer declaration in the AstraNull portal. No provider credentials, account inventory, or automatic discovery were used.</p>
            <div className="form-actions">
              <AnchorButton href="#targets" variant="secondary">View target inventory</AnchorButton>
              <Button type="button" onClick={closeAddDomain}>Done</Button>
            </div>
          </div>
        ) : (
          <form className="product-form" onSubmit={handleAddSingleDomain} aria-busy={busy === 'add-single-domain' || undefined}>
            <fieldset disabled={busy === 'add-single-domain'}>
              <div className="domain-scope-options full" role="radiogroup" aria-label="Target group destination">
                <label className="domain-scope-option">
                  <input
                    type="radio"
                    name="scope_mode"
                    value="existing"
                    checked={domainScopeMode === 'existing'}
                    onChange={() => setDomainScopeMode('existing')}
                    disabled={targetGroupRecords.length === 0}
                  />
                  <span><strong>Existing target group</strong><span>Attach the domain to customer-declared scope already in AstraNull.</span></span>
                </label>
                <label className="domain-scope-option">
                  <input type="radio" name="scope_mode" value="new" checked={domainScopeMode === 'new'} onChange={() => setDomainScopeMode('new')} />
                  <span><strong>Create new group</strong><span>Create the declared scope first, then add this domain to it.</span></span>
                </label>
              </div>

              {domainScopeMode === 'existing' ? (
                <div className="full">
                  {targetGroupsLoadError ? (
                    <div className="form-banner error" role="alert">
                      <span>Could not refresh target groups — {targetGroupsLoadError}. Previously loaded choices may be stale.</span>
                      <Button type="button" size="sm" variant="ghost" onClick={() => void onRefresh()}>Retry</Button>
                    </div>
                  ) : null}
                  {targetGroupRecords.length > 0 ? (
                    <label className="full">
                      <span>Target group</span>
                      <select
                        name="target_group_id"
                        value={effectiveDomainTargetGroupId}
                        onChange={(event) => setDomainTargetGroupId(event.target.value)}
                        required
                      >
                        {targetGroupRecords.map((group) => {
                          const id = getString(group, ['id'], '');
                          return <option key={id} value={id}>{getString(group, ['name'], id)}</option>;
                        })}
                      </select>
                    </label>
                  ) : targetGroupsLoadError ? null : (
                    <CalloutNote icon={Target} tone="info">No target groups are configured. Choose Create new group to declare scope here.</CalloutNote>
                  )}
                </div>
              ) : (
                <>
                  <label>
                    <span>New target group name</span>
                    <input name="group_name" placeholder="Checkout production" maxLength={120} required />
                  </label>
                  <div>
                    {environmentsLoading ? (
                      <div className="form-banner info" role="status">Loading environments…</div>
                    ) : environmentError ? (
                      <div className="form-banner error" role="alert">
                        <span>{environmentError}</span>
                        <Button type="button" size="sm" variant="ghost" onClick={() => void retryEnvironmentLoad()}>Retry</Button>
                      </div>
                    ) : tenantEnvironments.length === 0 ? (
                      <div className="form-banner info">
                        <span>No environments are configured. Create one before declaring a new target group.</span>
                        <AnchorButton href="#environments" size="sm" variant="ghost">Open environments</AnchorButton>
                      </div>
                    ) : (
                      <label>
                        <span>Environment</span>
                        <select value={effectiveEnvironmentId} onChange={(event) => setSelectedEnvironmentId(event.target.value)} required>
                          {tenantEnvironments.map((environment) => {
                            const id = getString(environment, ['id'], '');
                            return <option key={id} value={id}>{getString(environment, ['name'], id)}</option>;
                          })}
                        </select>
                      </label>
                    )}
                  </div>
                </>
              )}

              <label className="full">
                <span>Hostname</span>
                <input
                  name="hostname"
                  className="mono"
                  placeholder="checkout.example.com"
                  autoCapitalize="none"
                  autoCorrect="off"
                  spellCheck={false}
                  inputMode="url"
                  required
                  autoFocus
                />
              </label>
              <label className="full">
                <span>Expected behavior</span>
                <select name="expected_behavior" defaultValue="block_at_edge" required>
                  <option value="block_at_edge">Block at edge</option>
                  <option value="absorb_at_origin">Absorb at origin</option>
                  <option value="rate_shape">Rate shape</option>
                </select>
              </label>
              <div className="domain-provenance full">
                <strong>Recorded provenance:</strong> manual customer declaration via AstraNull Integrations; provider access: none. The target starts unverified and cannot receive external probes until ownership is proven.
              </div>
              <div className="form-actions full">
                <Button type="button" variant="ghost" disabled={busy !== ''} onClick={closeAddDomain}>Cancel</Button>
                <Button
                  type="submit"
                  loading={busy === 'add-single-domain'}
                  disabled={busy !== '' || (domainScopeMode === 'existing' ? !effectiveDomainTargetGroupId : !effectiveEnvironmentId || environmentsLoading || Boolean(environmentError))}
                >
                  {domainScopeMode === 'new' ? 'Create group & add domain' : 'Add declared domain'}
                </Button>
              </div>
            </fieldset>
          </form>
        )}
      </FormModal>
    </div>
  );
}

export function SupportPage({ data, session }: { data: PortalData; session: Session }) {
  const summary = data.subscriptionSummary;
  const support = getNestedItem(summary, ['support']);
  const usage = getNestedItem(summary, ['usage']);
  const account = getNestedItem(summary, ['account']);
  const recentAudit = getNestedArray(support, ['recent_audit']);
  const openFindings = getNumber(usage ?? {}, ['open_findings']);
  const pendingHighScale = getNumber(usage ?? {}, ['pending_high_scale_requests']);
  const supportOwner = getString(support ?? {}, ['owner'], 'Unassigned');
  const escalationState = getString(support ?? {}, ['escalation_state'], summary ? 'nominal' : 'No record');
  const routeAccessContext = {
    principal: session.principal,
    staffRole: session.staff_role,
  };
  const role = session.role ?? 'admin';
  const canReadNotifications = canAccessRoute(role, 'notifications', routeAccessContext);
  const supportRows = summary
    ? [
        { label: 'Support owner', value: supportOwner, icon: LifeBuoy },
        { label: 'Account lifecycle', value: getString(account ?? support ?? {}, ['lifecycle_state'], 'unrecorded'), icon: ShieldCheck },
        { label: 'Region', value: getString(account ?? support ?? {}, ['region'], 'unrecorded'), icon: Network },
        { label: 'Recent tenant audit records', value: formatNumber(getNumber(usage ?? {}, ['audit_events'])), icon: FileCheck2 }
      ]
    : [];

  return (
    <div className="content">
      <PageHeader
        route="support"
        eyebrow="Readiness support"
        actions={<AnchorButton href={SUPPORT_CONTACT_MAILTO} variant="default" size="sm">Contact support</AnchorButton>}
      />
      <PageContextSummary>
        Owner {summary ? supportOwner : '—'} ·{' '}
        <span className="tabular-nums">{summary ? openFindings : '—'}</span> open findings ·{' '}
        <span className="tabular-nums">{summary ? pendingHighScale : '—'}</span> SOC escalations
        {summary ? ` (${escalationState.replaceAll('_', ' ')})` : ''}
      </PageContextSummary>
      <div className="split">
        <Card>
          <CardHeader>
            <CardTitle>Support readiness</CardTitle>
            <CardDescription>Tenant support posture from account, findings, high-scale, and audit records.</CardDescription>
          </CardHeader>
          <CardContent className="settings-list">
            {supportRows.length === 0 ? (
              <EmptyState icon={LifeBuoy} title="No support account record." body="Approve a signup request or attach tenant account metadata before support readiness can show live ownership." />
            ) : supportRows.map(({ label, value, icon: RowIcon }) => (
              <div key={label}>
                <RowIcon size={18} aria-hidden />
                <span>
                  <strong>{label}</strong>
                  {' — '}
                  {label === 'Account lifecycle'
                    ? <Badge tone={lifecycleBadgeTone(value)}>{value}</Badge>
                    : value}
                </span>
              </div>
            ))}
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>Recent support evidence</CardTitle>
            <CardDescription>Latest tenant audit events exposed as metadata-only support context.</CardDescription>
          </CardHeader>
          <CardContent className="queue-list support-evidence-list">
            {recentAudit.length === 0 ? (
              <EmptyState icon={FileCheck2} title="No recent support evidence." body="Tenant audit entries will appear here after support-relevant actions are recorded." />
            ) : recentAudit.map((entry) => {
              const action = getString(entry, ['action'], '—');
              const resourceType = getString(entry, ['resource_type'], 'audit');
              return (
                <div key={getString(entry, ['id', 'created_at', 'action'])} className="support-evidence-item">
                  <div className="support-evidence-main">
                    <span className="support-evidence-type">{formatResourceTypeLabel(resourceType)}</span>
                    <span className="support-evidence-action">{formatAuditAction(action, action)}</span>
                  </div>
                  <div className="support-evidence-meta">
                    <span className="muted">{formatDate(entry.created_at)}</span>
                    <AnchorButton size="sm" variant="ghost" href="#audit">View</AnchorButton>
                  </div>
                </div>
              );
            })}
          </CardContent>
        </Card>
      </div>
      <Card>
        <CardHeader>
          <CardTitle>Support workflows</CardTitle>
          <CardDescription>Customer escalation paths within authorized validation boundaries.</CardDescription>
        </CardHeader>
        <CardContent className="row-actions">
          <AnchorButton href="#findings" variant="secondary" size="sm">Review open findings ({openFindings})</AnchorButton>
          <AnchorButton href="#runs" variant="secondary" size="sm">Request SOC-governed test ({pendingHighScale} pending)</AnchorButton>
          {canReadNotifications ? <AnchorButton href="#notifications" variant="secondary" size="sm">Notification rules</AnchorButton> : null}
        </CardContent>
      </Card>
    </div>
  );
}

const ENTITLEMENT_FEATURES = ['waf_posture', 'external_discovery', 'connectors', 'high_scale_program'] as const;

const ENTITLEMENT_FEATURE_LABELS: Record<(typeof ENTITLEMENT_FEATURES)[number], string> = {
  waf_posture: 'WAF posture',
  external_discovery: 'External discovery',
  connectors: 'Connectors',
  high_scale_program: 'High-scale program'
};

const SUBSCRIPTION_PAGE_STYLES = `
.subscription-page .subscription-toolbar,
.subscription-page .subscription-plan-heading,
.subscription-page .subscription-usage-card-head,
.subscription-page .subscription-signal-strip,
.subscription-page .subscription-state-error,
.subscription-page .subscription-entitlement-indicator {
  display: flex;
  align-items: center;
  gap: var(--space-3);
}
.subscription-page .subscription-toolbar,
.subscription-page .subscription-plan-heading,
.subscription-page .subscription-usage-card-head,
.subscription-page .subscription-state-error {
  justify-content: space-between;
}
.subscription-page .subscription-toolbar {
  flex-wrap: wrap;
  margin-bottom: var(--space-3);
  padding: var(--space-3) var(--space-4);
  border: 1px solid var(--border-soft);
  border-radius: var(--radius-md);
  background: var(--proof-surface);
}
.subscription-page .subscription-freshness {
  display: inline-flex;
  align-items: center;
  gap: var(--space-2);
  color: var(--fg-2);
  font-size: var(--text-xs);
}
.subscription-page .subscription-plan-heading {
  align-items: flex-start;
}
.subscription-page .subscription-plan-title {
  display: flex;
  min-width: 0;
  flex-direction: column;
  gap: var(--space-1);
}
.subscription-page .subscription-plan-title .eyebrow {
  margin: 0;
}
.subscription-page .subscription-plan-facts {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 1px;
  margin: 0;
  overflow: hidden;
  border: 1px solid var(--border-soft);
  border-radius: var(--radius-md);
  background: var(--border-soft);
}
.subscription-page .subscription-plan-fact {
  min-width: 0;
  padding: var(--space-3) var(--space-4);
  background: var(--surface);
}
.subscription-page .subscription-plan-fact dt {
  margin-bottom: var(--space-1);
  color: var(--muted);
  font-size: var(--text-xs);
}
.subscription-page .subscription-plan-fact dd {
  min-width: 0;
  margin: 0;
  color: var(--fg);
  font-size: var(--text-sm);
  font-weight: 600;
  overflow-wrap: anywhere;
}
.subscription-page .subscription-usage-grid {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: var(--space-3);
}
.subscription-page .subscription-usage-card {
  display: flex;
  min-width: 0;
  flex-direction: column;
  gap: var(--space-3);
  padding: var(--space-4);
  border: 1px solid var(--border-soft);
  border-radius: var(--radius-md);
  background: var(--proof-surface);
}
.subscription-page .subscription-usage-copy,
.subscription-page .subscription-usage-value {
  display: flex;
  min-width: 0;
  flex-direction: column;
  gap: var(--space-1);
}
.subscription-page .subscription-usage-copy strong,
.subscription-page .subscription-usage-value strong {
  color: var(--fg);
  font-size: var(--text-sm);
}
.subscription-page .subscription-usage-copy span,
.subscription-page .subscription-usage-value span,
.subscription-page .subscription-limit-note {
  color: var(--muted);
  font-size: var(--text-xs);
}
.subscription-page .subscription-usage-value strong {
  font-family: var(--font-display);
  font-size: var(--text-xl);
  font-variant-numeric: tabular-nums;
}
.subscription-page .subscription-limit-note {
  margin: auto 0 0;
  line-height: 1.45;
}
.subscription-page .subscription-signal-strip {
  flex-wrap: wrap;
  margin-top: var(--space-4);
  padding-top: var(--space-4);
  border-top: 1px solid var(--border-soft);
}
.subscription-page .subscription-signal-strip > strong {
  color: var(--fg-2);
  font-size: var(--text-xs);
}
.subscription-page .subscription-signal-item {
  display: inline-flex;
  align-items: center;
  gap: var(--space-2);
  color: var(--fg-2);
  font-size: var(--text-xs);
}
.subscription-page .subscription-entitlement-indicator {
  display: inline-flex;
  width: max-content;
  max-width: 100%;
  gap: var(--space-2);
  color: var(--muted);
  font-size: var(--text-sm);
  font-weight: 600;
}
.subscription-page .subscription-entitlement-indicator[data-state='enabled'] {
  color: var(--success);
}
.subscription-page .subscription-entitlement-indicator[data-state='disabled'] {
  color: var(--fg-2);
}
.subscription-page .subscription-entitlement-indicator[data-state='unknown'] {
  color: var(--warn);
}
.subscription-page .subscription-state-error {
  align-items: flex-start;
  padding: var(--space-4);
  border: 1px solid var(--danger);
  border-radius: var(--radius-md);
  background: color-mix(in oklab, var(--danger), transparent 92%);
}
.subscription-page .subscription-state-error > div {
  display: flex;
  min-width: 0;
  gap: var(--space-3);
}
.subscription-page .subscription-state-error h2,
.subscription-page .subscription-state-error p {
  margin: 0;
}
.subscription-page .subscription-state-error h2 {
  color: var(--fg);
  font-size: var(--text-base);
}
.subscription-page .subscription-state-error p {
  margin-top: var(--space-1);
  color: var(--fg-2);
  font-size: var(--text-sm);
}
@media (max-width: 960px) {
  .subscription-page .subscription-plan-facts,
  .subscription-page .subscription-usage-grid {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }
}
@media (max-width: 620px) {
  .subscription-page .subscription-toolbar,
  .subscription-page .subscription-plan-heading,
  .subscription-page .subscription-usage-card-head,
  .subscription-page .subscription-state-error {
    align-items: flex-start;
    flex-direction: column;
  }
  .subscription-page .subscription-plan-facts,
  .subscription-page .subscription-usage-grid {
    grid-template-columns: 1fr;
  }
  .subscription-page .subscription-toolbar .btn,
  .subscription-page .subscription-state-error .btn {
    width: 100%;
  }
}
`;

function formatEntitlementGrantSource(value: string) {
  if (!value || value === 'plan only') return 'Plan default';
  if (value.startsWith('plan:')) return `Plan default (${value.slice(5)})`;
  return value;
}

function subscriptionRecordedTimestamp(...values: unknown[]) {
  for (const value of values) {
    if (typeof value === 'string' && Number.isFinite(Date.parse(value))) return value;
  }
  return '';
}

function SubscriptionEntitlementIndicator({
  value,
  enabledLabel,
  disabledLabel
}: {
  value: unknown;
  enabledLabel: string;
  disabledLabel: string;
}) {
  const state = value === true ? 'enabled' : value === false ? 'disabled' : 'unknown';
  const label = value === true ? enabledLabel : value === false ? disabledLabel : 'Not recorded';
  const Icon = value === true ? CheckCircle2 : value === false ? CircleMinus : CircleHelp;
  return (
    <span className="subscription-entitlement-indicator" data-state={state} aria-label={label}>
      <Icon size={15} aria-hidden="true" />
      <span>{label}</span>
    </span>
  );
}

export function SubscriptionPage({ data }: { data: PortalData }) {
  const [portalLoadedAt] = useState(() => new Date().toISOString());
  const summary = data.subscriptionSummary;
  const subscriptionLoadError = data.loadErrors.subscriptionSummary;
  const subscription = getNestedItem(summary, ['subscription']);
  const plan = getNestedItem(summary, ['plan']);
  const account = getNestedItem(summary, ['account']);
  const usage = getNestedItem(summary, ['usage']);
  const support = getNestedItem(summary, ['support']);
  const planEntitlements = getNestedItem(plan, ['feature_entitlements']) ?? getNestedItem(subscription, ['feature_entitlements']);
  const effectiveEntitlements = getNestedItem(subscription, ['effective_entitlements']);
  const entitlementGrants = Array.isArray(subscription?.entitlement_grants) ? subscription.entitlement_grants as DataItem[] : [];
  const hasSubscription = Boolean(subscription);
  const planLabel = hasSubscription ? getString(plan ?? {}, ['name'], getString(subscription ?? {}, ['plan_id'], 'Recorded plan')) : 'Not configured';
  const readUsage = (key: string) => {
    const value = usage?.[key];
    return typeof value === 'number' && Number.isFinite(value) ? value : null;
  };
  const safeRunsLimit = getNestedNumber(subscription, ['limits', 'safe_runs_per_hour'], -1);
  const safeRunsUsed = readUsage('safe_runs_started_last_hour');
  const targetGroupLimit = getNestedNumber(subscription, ['limits', 'target_groups'], -1);
  const targetGroupUsage = readUsage('target_groups');
  const usersLimit = getNestedNumber(subscription, ['limits', 'users'], -1);
  const usersUsed = readUsage('users');
  const agentsLimit = getNestedNumber(subscription, ['limits', 'agents'], -1);
  const agentsUsed = readUsage('agents');
  const highScaleMonthLimit = getNestedNumber(subscription, ['limits', 'high_scale_requests_per_month'], -1);
  const highScaleMonthUsed = readUsage('high_scale_requests_this_month');
  const openFindings = readUsage('open_findings');
  const pendingHighScale = readUsage('pending_high_scale_requests');
  const subscriptionStatus = getString(subscription ?? {}, ['status'], 'unrecorded');
  const highScaleEntitlement = effectiveEntitlements?.high_scale_program;
  const highScaleLabel = highScaleEntitlement === true ? 'enabled' : highScaleEntitlement === false ? 'disabled' : 'not recorded';
  const supportOwner = getString(support ?? account ?? {}, ['owner', 'support_owner'], 'unassigned');
  const sourceTimestamp = subscriptionRecordedTimestamp(
    summary?.generated_at,
    summary?.as_of,
    usage?.as_of,
    usage?.observed_at
  );
  const subscriptionRecordTimestamp = subscriptionRecordedTimestamp(subscription?.updated_at);
  const freshnessLabel = sourceTimestamp
    ? `Source snapshot ${formatDate(sourceTimestamp)}`
    : subscriptionRecordTimestamp
      ? `Subscription record updated ${formatDate(subscriptionRecordTimestamp)} · usage snapshot timestamp not provided`
      : `Portal loaded ${formatDate(portalLoadedAt)} · source timestamp not provided`;
  const entitlementRows: DataItem[] = ENTITLEMENT_FEATURES.map((feature) => {
    const grant = entitlementGrants.find((entry) => getString(entry, ['feature'], '') === feature);
    const planValue = planEntitlements?.[feature];
    const effectiveValue = effectiveEntitlements?.[feature];
    const normalizedPlanValue = typeof planValue === 'boolean' ? planValue : null;
    const normalizedEffectiveValue = typeof effectiveValue === 'boolean' ? effectiveValue : null;
    return {
      feature,
      plan_enabled: normalizedPlanValue,
      effective_enabled: normalizedEffectiveValue,
      grant_source: grant
        ? getString(grant, ['source'], 'staff grant')
        : normalizedPlanValue === null ? 'not recorded' : 'plan only'
    };
  });
  const recordedEntitlements = entitlementRows.filter((row) => typeof row.effective_enabled === 'boolean');
  const enabledEntitlements = recordedEntitlements.filter((row) => row.effective_enabled === true).length;
  const usageRows = [
    { label: 'Target groups', description: 'Declared validation scopes', used: targetGroupUsage, limit: targetGroupLimit },
    { label: 'Users', description: 'Workspace members', used: usersUsed, limit: usersLimit },
    { label: 'Agents', description: 'Registered observation agents', used: agentsUsed, limit: agentsLimit },
    { label: 'Runs', description: 'Started in the current hour', used: safeRunsUsed, limit: safeRunsLimit },
    { label: 'High-scale requests', description: 'Current month · SOC-gated', used: highScaleMonthUsed, limit: highScaleMonthLimit }
  ];
  const recordedUsageCount = usageRows.filter((row) => row.used !== null).length;
  const entitlementColumns: TableColumn<DataItem>[] = [
    {
      key: 'feature',
      label: 'Feature',
      render: (item) => {
        const feature = getString(item, ['feature']);
        return <strong>{ENTITLEMENT_FEATURE_LABELS[feature as (typeof ENTITLEMENT_FEATURES)[number]] ?? feature}</strong>;
      }
    },
    {
      key: 'plan',
      label: 'Plan inclusion',
      render: (item) => (
        <SubscriptionEntitlementIndicator value={item.plan_enabled} enabledLabel="Included" disabledLabel="Not included" />
      )
    },
    {
      key: 'effective',
      label: 'Effective access (authoritative)',
      render: (item) => (
        <SubscriptionEntitlementIndicator value={item.effective_enabled} enabledLabel="Enabled" disabledLabel="Disabled" />
      )
    },
    {
      key: 'grant',
      label: 'Access source',
      render: (item) => formatEntitlementGrantSource(getString(item, ['grant_source'], 'not recorded'))
    }
  ];
  const refreshPage = () => window.location.reload();

  if (subscriptionLoadError) {
    return (
      <div className="content subscription-page">
        <style>{SUBSCRIPTION_PAGE_STYLES}</style>
        <PageHeader route="subscription" eyebrow="Plan & usage" />
        <Card>
          <CardContent>
            <div className="subscription-state-error" role="alert">
              <div>
                <TriangleAlert size={20} aria-hidden="true" />
                <div>
                  <h2>Subscription data could not be loaded</h2>
                  <p>{subscriptionLoadError} Existing limits and entitlements are not shown as an empty account.</p>
                </div>
              </div>
              <Button type="button" variant="secondary" onClick={refreshPage}><RefreshCw size={15} aria-hidden="true" /> Retry</Button>
            </div>
          </CardContent>
        </Card>
      </div>
    );
  }

  if (!data.loaded) {
    return (
      <div className="content subscription-page">
        <style>{SUBSCRIPTION_PAGE_STYLES}</style>
        <PageHeader route="subscription" eyebrow="Plan & usage" />
        <EmptyState
          icon={Activity}
          variant="skeleton"
          title="Loading subscription…"
          body="Fetching the authoritative plan, effective entitlements, and current usage snapshot."
        />
      </div>
    );
  }

  if (!hasSubscription) {
    return (
      <div className="content subscription-page">
        <style>{SUBSCRIPTION_PAGE_STYLES}</style>
        <PageHeader
          route="subscription"
          eyebrow="Entitlements"
          actions={<Button type="button" variant="secondary" size="sm" onClick={refreshPage}><RefreshCw size={15} aria-hidden="true" /> Refresh</Button>}
        />
        <EmptyState
          icon={LifeBuoy}
          title="No subscription configured for this tenant."
          body="The subscription API loaded successfully but returned no subscription record. Contact AstraNull support for provisioning or billing assistance."
          actionLabel="Open support workspace"
          actionHref="#support"
        />
      </div>
    );
  }

  return (
    <div className="content subscription-page">
      <style>{SUBSCRIPTION_PAGE_STYLES}</style>
      <PageHeader route="subscription" eyebrow="Plan & usage" />
      <div className="subscription-toolbar" role="status" aria-live="polite">
        <span className="subscription-freshness"><Activity size={14} aria-hidden="true" /> {freshnessLabel}</span>
        <Button type="button" variant="secondary" size="sm" onClick={refreshPage} title="Reload the page to request a fresh subscription snapshot.">
          <RefreshCw size={15} aria-hidden="true" /> Refresh
        </Button>
      </div>
      <PageContextSummary>
        {planLabel} · runs{' '}
        <span className="tabular-nums">
          {safeRunsUsed === null ? 'not recorded' : `${safeRunsUsed}${safeRunsLimit >= 0 ? ` / ${safeRunsLimit}` : ''}`}
        </span>{' '}
        per hour · high-scale program {highScaleLabel}
      </PageContextSummary>

      <Card className="subscription-plan-surface">
        <CardHeader>
          <div className="subscription-plan-heading">
            <div className="subscription-plan-title">
              <p className="eyebrow">Current plan</p>
              <CardTitle>{planLabel}</CardTitle>
              <CardDescription>Contract posture and account ownership, without duplicating usage or entitlement panels.</CardDescription>
            </div>
            <Badge tone={subscriptionStatusBadgeTone(subscriptionStatus)}>{subscriptionStatus.replaceAll('_', ' ')}</Badge>
          </div>
        </CardHeader>
        <CardContent>
          <dl className="subscription-plan-facts">
            <div className="subscription-plan-fact">
              <dt>Effective</dt>
              <dd>{formatDate(subscription?.effective_at)}</dd>
            </div>
            <div className="subscription-plan-fact">
              <dt>Renewal</dt>
              <dd>{formatDate(subscription?.renewal_at)}</dd>
            </div>
            <div className="subscription-plan-fact">
              <dt>Data region</dt>
              <dd>{getString(account ?? support ?? {}, ['region'], 'unrecorded')}</dd>
            </div>
            <div className="subscription-plan-fact">
              <dt>Lifecycle</dt>
              <dd><Badge tone={lifecycleBadgeTone(getString(account ?? support ?? {}, ['lifecycle_state'], 'unrecorded'))}>{getString(account ?? support ?? {}, ['lifecycle_state'], 'unrecorded')}</Badge></dd>
            </div>
            <div className="subscription-plan-fact">
              <dt>Support owner</dt>
              <dd>{getString(account ?? {}, ['support_owner'], supportOwner)}</dd>
            </div>
            <div className="subscription-plan-fact">
              <dt>Contract ref</dt>
              <dd>{getString(account ?? {}, ['contract_reference'], 'unrecorded')}</dd>
            </div>
          </dl>
        </CardContent>
      </Card>

      <Card className="card--dense">
        <PanelCardHeader
          title="Usage against plan limits"
          description="Each card joins the recorded count, authoritative limit, and progress state."
          trailing={<Badge tone={recordedUsageCount === usageRows.length ? 'info' : 'muted'}>{recordedUsageCount} / {usageRows.length} recorded</Badge>}
        />
        <CardContent>
          {usage ? (
            <>
              <div className="subscription-usage-grid" role="list" aria-label="Subscription usage">
                {usageRows.map((row) => {
                  const hasUsage = row.used !== null;
                  const hasLimit = row.limit >= 0;
                  const percent = hasUsage && hasLimit
                    ? row.limit > 0 ? Math.min(100, Math.round((row.used! / row.limit) * 100)) : row.used! > 0 ? 100 : 0
                    : null;
                  const atLimit = hasUsage && hasLimit && (row.limit === 0 ? row.used! > 0 : row.used! >= row.limit);
                  return (
                    <article className="subscription-usage-card" role="listitem" key={row.label}>
                      <div className="subscription-usage-card-head">
                        <div className="subscription-usage-copy">
                          <strong>{row.label}</strong>
                          <span>{row.description}</span>
                        </div>
                        <Badge tone={percent === null ? 'muted' : atLimit ? 'warn' : 'info'}>
                          {percent === null ? 'No measure' : `${percent}%`}
                        </Badge>
                      </div>
                      <div className="subscription-usage-value" aria-label={`${row.label} count and limit`}>
                        <strong>{hasUsage ? formatNumber(row.used!) : 'Not recorded'}</strong>
                        <span>{hasUsage ? (hasLimit ? `of ${formatNumber(row.limit)}` : 'used · limit not recorded') : 'Usage unavailable'}</span>
                      </div>
                      {percent !== null ? (
                        <Progress
                          value={percent}
                          tone={atLimit ? 'warn' : 'accent'}
                          label={`${row.label} usage, ${row.used} of ${row.limit}`}
                        />
                      ) : (
                        <p className="subscription-limit-note">Progress is unavailable until both usage and a plan limit are recorded.</p>
                      )}
                    </article>
                  );
                })}
              </div>
              <div className="subscription-signal-strip" aria-label="Workspace signals that are not subscription limits">
                <strong>Workspace signals · not plan limits</strong>
                <span className="subscription-signal-item">Open findings <Badge tone={openFindings === null ? 'muted' : openFindings > 0 ? 'warn' : 'success'}>{openFindings === null ? 'Not recorded' : formatNumber(openFindings)}</Badge></span>
                <span className="subscription-signal-item">Pending high-scale <Badge tone={pendingHighScale === null ? 'muted' : pendingHighScale > 0 ? 'warn' : 'muted'}>{pendingHighScale === null ? 'Not recorded' : formatNumber(pendingHighScale)}</Badge></span>
              </div>
            </>
          ) : (
            <EmptyState icon={Activity} title="No usage snapshot recorded." body="Plan metadata is available, but the subscription API did not return workspace usage counts." />
          )}
        </CardContent>
      </Card>

      <Card className="card--dense">
        <PanelCardHeader
          title="Effective entitlements"
          description="Effective access is the authoritative subscription API result. Plan inclusion and access source explain how it was derived."
          trailing={
            <Badge tone={recordedEntitlements.length > 0 && enabledEntitlements > 0 ? 'success' : 'muted'}>
              {recordedEntitlements.length > 0 ? `${enabledEntitlements} / ${recordedEntitlements.length} enabled` : 'Not recorded'}
            </Badge>
          }
        />
        <CardContent>
          <DataTable
            columns={entitlementColumns}
            items={entitlementRows}
            empty={<EmptyState icon={ShieldCheck} title="No entitlement definitions." body="The subscription catalog did not return any recognized feature definitions." />}
          />
        </CardContent>
      </Card>
    </div>
  );
}

export function StaffSurfacePage({
  route,
  data,
  config,
  session,
  onRefresh
}: {
  route: RouteId;
  data: PortalData;
  config: PortalConfig;
  session: Session;
  onRefresh: () => Promise<void>;
}) {
  const [busy, setBusy] = useState('');
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');
  const [entitlementTenantId, setEntitlementTenantId] = useState(() => getString(data.internalTenants[0] ?? {}, ['tenant_id', 'id'], ''));
  const [entitlementFeature, setEntitlementFeature] = useState('waf_posture');
  const [entitlementAction, setEntitlementAction] = useState('true');
  const [subscriptionSnapshot, setSubscriptionSnapshot] = useState<DataItem | null>(null);
  const entitlementFeatures = ['waf_posture', 'external_discovery', 'connectors', 'high_scale_program'] as const;
  const internalTenantOptions: SelectOption[] = data.internalTenants.length > 0
    ? data.internalTenants.map((tenant) => {
      const tenantId = getString(tenant, ['tenant_id', 'id'], '');
      return {
        value: tenantId,
        label: getString(tenant, ['name', 'tenant_id'], tenantId)
      };
    })
    : [{ value: entitlementTenantId, label: entitlementTenantId || 'No tenant selected' }];
  const entitlementFeatureOptions: SelectOption[] = entitlementFeatures.map((feature) => ({
    value: feature,
    label: ENTITLEMENT_FEATURE_LABELS[feature] ?? feature
  }));
  const entitlementActionOptions: SelectOption[] = [
    { value: 'true', label: 'Grant / enable' },
    { value: 'false', label: 'Revoke / disable' }
  ];
  const isStaff = session.principal === 'staff';
  const [adminTab, setAdminTab] = useState('signup-queue');
  const adminTabOptions = routeTabs('admin').map((tab) => ({ id: tab.id, label: tab.label }));
  const overview = data.internalOverview;
  const queueDepth = getNumber(overview ?? {}, ['pending_signups']) + getNumber(overview ?? {}, ['pending_approval_requests']);
  const tenantCount = getNumber(overview ?? {}, ['tenant_count'], data.internalTenants.length);
  const highScaleReviews = getNumber(overview ?? {}, ['high_scale_reviews']);
  async function runStaffAction<T>(label: string, action: () => Promise<T>, success: string) {
    setBusy(label);
    setError('');
    setMessage('');
    try {
      const result = await action();
      setMessage(success);
      await onRefresh();
      return result;
    } catch (err) {
      setError(apiErrorMessage(err, 'Staff action failed.'));
      return null;
    } finally {
      setBusy('');
    }
  }

  async function approveSignup(id: string) {
    if (!window.confirm('Approve this signup request? A tenant account will be provisioned.')) return;
    await runStaffAction(`approve-signup-${id}`, () => requestJson(config, session, `/internal/admin/signup-requests/${id}/approve`, {
      method: 'POST',
      body: { reason: 'Approved from React staff console.' }
    }), 'Signup request approved and tenant provisioned.');
  }

  async function rejectSignup(id: string) {
    if (!window.confirm('Reject this signup request? No tenant will be provisioned for this applicant.')) return;
    await runStaffAction(`reject-signup-${id}`, () => requestJson(config, session, `/internal/admin/signup-requests/${id}/reject`, {
      method: 'POST',
      body: { reason: 'Rejected from React staff console.' }
    }), 'Signup request rejected.');
  }

  async function decideApproval(id: string, decision: 'approve' | 'reject') {
    if (decision === 'approve') {
      if (!window.confirm('Approve this internal approval request? The requested action will proceed.')) return;
    } else if (!window.confirm('Reject this internal approval request? The requested action will not proceed.')) return;
    await runStaffAction(`approval-${id}-${decision}`, () => requestJson(config, session, `/internal/admin/approval-requests/${id}/decision`, {
      method: 'POST',
      body: { decision, reason: `${decision} from React staff console.` }
    }), `Approval request ${decision}d.`);
  }

  useEffect(() => {
    if (!isStaff || !entitlementTenantId) {
      setSubscriptionSnapshot(null);
      return;
    }
    let cancelled = false;
    requestJson(config, session, `/internal/admin/tenants/${encodeURIComponent(entitlementTenantId)}/subscription`)
      .then((payload) => {
        if (!cancelled) setSubscriptionSnapshot(payload as DataItem);
      })
      .catch(() => {
        if (!cancelled) setSubscriptionSnapshot(null);
      });
    return () => {
      cancelled = true;
    };
  }, [config, session, entitlementTenantId, isStaff, data.internalTenants]);

  async function grantEntitlement(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const feature = String(form.get('feature') ?? '').trim();
    const enabled = String(form.get('enabled') ?? 'true') === 'true';
    const reason = String(form.get('reason') ?? '').trim();
    if (!entitlementTenantId || !feature) {
      setError('Select a tenant and feature before granting entitlements.');
      return;
    }
    const featureLabel = ENTITLEMENT_FEATURE_LABELS[feature as (typeof ENTITLEMENT_FEATURES)[number]] ?? feature;
    if (enabled) {
      if (!window.confirm(`Grant the ${featureLabel} entitlement for this tenant?`)) return;
    } else if (!window.confirm(`Revoke the ${featureLabel} entitlement? The feature will be disabled for this tenant.`)) return;
    await runStaffAction(`entitlement-${entitlementTenantId}-${feature}`, () => requestJson(config, session, `/internal/admin/tenants/${encodeURIComponent(entitlementTenantId)}/entitlements`, {
      method: 'POST',
      body: { feature, enabled, reason: reason || `Entitlement ${enabled ? 'granted' : 'revoked'} from React staff console.` }
    }), `${feature} entitlement ${enabled ? 'granted' : 'revoked'} for ${entitlementTenantId}.`);
  }

  const effectiveEntitlements = getNestedItem(subscriptionSnapshot, ['effective_entitlements'])
    ?? getNestedItem(subscriptionSnapshot, ['subscription', 'effective_entitlements']);

  const signupColumns: TableColumn<DataItem>[] = [
    { key: 'org', label: 'Organization', render: (item) => getString(item, ['organization_name', 'id']) },
    { key: 'state', label: 'State', render: (item) => <Badge tone={['submitted', 'under_review'].includes(getString(item, ['state'])) ? 'warn' : 'info'}>{getString(item, ['state'])}</Badge> },
    { key: 'plan', label: 'Plan', render: (item) => getString(item, ['requested_plan']) },
    { key: 'created', label: 'Created', render: (item) => formatDate(item.created_at) },
    {
      key: 'actions',
      label: 'Actions',
      render: (item) => {
        const id = getString(item, ['id'], '');
        const state = getString(item, ['state'], '');
        if (!['submitted', 'under_review'].includes(state)) return '—';
        const rowBusy = busy === `approve-signup-${id}` || busy === `reject-signup-${id}`;
        const rowBlocked = busy !== '' && !rowBusy;
        return (
          <div className="row-actions" aria-busy={rowBusy || undefined}>
            <Button size="sm" variant="secondary" loading={busy === `approve-signup-${id}`} disabled={rowBlocked} onClick={() => void approveSignup(id)}>Approve</Button>
            <Button size="sm" variant="danger" loading={busy === `reject-signup-${id}`} disabled={rowBlocked} onClick={() => void rejectSignup(id)}>Reject</Button>
          </div>
        );
      }
    }
  ];
  const tenantColumns: TableColumn<DataItem>[] = [
    { key: 'tenant', label: 'Tenant', render: (item) => getString(item, ['name', 'tenant_id']) },
    { key: 'state', label: 'Lifecycle', render: (item) => <Badge tone={getString(item, ['lifecycle_state']) === 'active' ? 'success' : 'warn'}>{getString(item, ['lifecycle_state'])}</Badge> },
    { key: 'plan', label: 'Plan', render: (item) => getString(item, ['plan_id']) },
    { key: 'owner', label: 'Support owner', render: (item) => getString(item, ['support_owner'], 'unassigned') },
    {
      key: 'actions',
      label: 'Actions',
      render: (item) => {
        const tenantId = getString(item, ['tenant_id', 'id'], '');
        return tenantId
          ? <AnchorButton size="sm" variant="secondary" href={buildDetailHref('tenant-detail', tenantId)}>Detail</AnchorButton>
          : '—';
      }
    }
  ];
  const approvalColumns: TableColumn<DataItem>[] = [
    { key: 'kind', label: 'Kind', render: (item) => getString(item, ['kind']) },
    { key: 'state', label: 'State', render: (item) => <Badge tone={['submitted', 'under_review'].includes(getString(item, ['state'])) ? 'warn' : 'success'}>{getString(item, ['state'])}</Badge> },
    { key: 'tenant', label: 'Tenant', render: (item) => getString(item, ['tenant_id']) },
    { key: 'created', label: 'Created', render: (item) => formatDate(item.created_at) },
    {
      key: 'actions',
      label: 'Actions',
      render: (item) => {
        const id = getString(item, ['id'], '');
        const state = getString(item, ['state'], '');
        if (!['submitted', 'under_review'].includes(state)) return '—';
        const rowBusy = busy === `approval-${id}-approve` || busy === `approval-${id}-reject`;
        const rowBlocked = busy !== '' && !rowBusy;
        return (
          <div className="row-actions" aria-busy={rowBusy || undefined}>
            <Button size="sm" variant="secondary" loading={busy === `approval-${id}-approve`} disabled={rowBlocked} onClick={() => void decideApproval(id, 'approve')}>Approve</Button>
            <Button size="sm" variant="danger" loading={busy === `approval-${id}-reject`} disabled={rowBlocked} onClick={() => void decideApproval(id, 'reject')}>Reject</Button>
          </div>
        );
      }
    }
  ];
  const auditColumns: TableColumn<DataItem>[] = [
    { key: 'action', label: 'Action', render: (item) => getString(item, ['action']) },
    { key: 'staff', label: 'Staff', render: (item) => getString(item, ['staff_id']) },
    { key: 'tenant', label: 'Tenant', render: (item) => getString(item, ['tenant_id']) },
    { key: 'created', label: 'Created', render: (item) => formatDate(item.created_at) }
  ];
  return (
    <div className="content">
      <PageHeader
        route={route}
        eyebrow={route === 'internal-soc' ? 'Staff SOC surface' : 'Staff-only surface'}
      />
      {(message || error) && <div className={error ? 'form-banner error' : 'form-banner'}>{error || message}</div>}
      <PageContextSummary>
        Review queue <span className="tabular-nums">{queueDepth}</span> ·{' '}
        <span className="tabular-nums">{tenantCount}</span> tenants ·{' '}
        <span className="tabular-nums">{highScaleReviews}</span> SOC reviews pending
      </PageContextSummary>
      {!isStaff ? (
        <Card>
          <CardHeader>
            <CardTitle>Staff session required</CardTitle>
            <CardDescription>Internal management data is only fetched after staff authentication.</CardDescription>
          </CardHeader>
          <CardContent>
            <EmptyState icon={UserCog} title="No staff principal." body="Use the staff sign-in surface to load internal management queues and audit records." actionLabel="Open staff login" actionHref="/internal/admin/login" />
          </CardContent>
        </Card>
      ) : (
        <>
          <Tabs value={adminTab} options={adminTabOptions} onChange={setAdminTab} className="tabs-wrap" />
          {adminTab === 'overview' ? (
            <Card density="compact">
              <CardHeader><CardTitle>Staff overview</CardTitle><CardDescription>Queue depth and tenant posture from internal management APIs.</CardDescription></CardHeader>
              <CardContent className="kv-list">
                <div><span>Review queue</span><strong>{queueDepth}</strong></div>
                <div><span>Tenants</span><strong>{tenantCount}</strong></div>
                <div><span>SOC reviews pending</span><strong>{highScaleReviews}</strong></div>
              </CardContent>
            </Card>
          ) : null}
          {adminTab === 'signup-queue' ? (
            <Card density="compact" className="staff-queue-priority">
              <CardHeader>
                <CardTitle>Signup queue</CardTitle>
                <CardDescription>Requests from the staff-only signup review API.</CardDescription>
              </CardHeader>
              <CardContent>
                <DataTable columns={signupColumns} items={data.internalSignupRequests} empty={renderFriendlyEmptyState({ icon: ClipboardList, title: 'No signup requests.', body: 'Reviewed account intake records will appear here after customers submit requests.' })} />
              </CardContent>
            </Card>
          ) : null}
          {adminTab === 'tenants' ? (
            <Card density="compact">
              <CardHeader>
                <CardTitle>Tenant directory</CardTitle>
                <CardDescription>Managed tenant account and subscription metadata.</CardDescription>
              </CardHeader>
              <CardContent>
                <DataTable columns={tenantColumns} items={data.internalTenants} empty={renderFriendlyEmptyState({ icon: Target, title: 'No managed tenants.', body: 'Provisioned tenants appear here after staff approval creates account records.' })} />
              </CardContent>
            </Card>
          ) : null}
          {adminTab === 'approvals' ? (
            <Card density="compact">
              <CardHeader>
                <CardTitle>Approval requests</CardTitle>
                <CardDescription>Unified internal approvals, including subscription exceptions.</CardDescription>
              </CardHeader>
              <CardContent>
                <DataTable columns={approvalColumns} items={data.internalApprovalRequests} empty={renderFriendlyEmptyState({ icon: ShieldCheck, title: 'No internal approvals.', body: 'Pending approval records will appear here when backend workflows create them.' })} loadError={data.loadErrors.internalApprovalRequests} onRetry={onRefresh ? () => void onRefresh() : undefined} />
              </CardContent>
            </Card>
          ) : null}
          {adminTab === 'audit' ? (
            <Card density="compact">
              <CardHeader>
                <CardTitle>Internal audit</CardTitle>
                <CardDescription>Recent staff actions from the internal audit API.</CardDescription>
              </CardHeader>
              <CardContent>
                <DataTable columns={auditColumns} items={data.internalAudit} empty={renderFriendlyEmptyState({ icon: FileCheck2, title: 'No internal audit events.', body: 'Staff decisions and support actions will be listed after they are recorded.' })} loadError={data.loadErrors.internalAudit} onRetry={onRefresh ? () => void onRefresh() : undefined} />
              </CardContent>
            </Card>
          ) : null}
          <Card>
            <CardHeader>
              <CardTitle>Support owner assignment</CardTitle>
              <CardDescription>Assign the AstraNull support owner for the selected tenant.</CardDescription>
            </CardHeader>
            <CardContent>
              <form className="product-form" onSubmit={(event) => {
                event.preventDefault();
                const owner = String(new FormData(event.currentTarget).get('support_owner') ?? '').trim();
                if (!entitlementTenantId || !owner) {
                  setError('Select a tenant before assigning a support owner.');
                  return;
                }
                if (!window.confirm(`Assign support owner "${owner}" for tenant ${entitlementTenantId}?`)) return;
                void runStaffAction(`support-owner-${entitlementTenantId}`, () => requestJson(config, session, `/internal/admin/tenants/${encodeURIComponent(entitlementTenantId)}`, {
                  method: 'PATCH',
                  body: { support_owner: owner, reason: 'Support owner updated from React staff console.' }
                }), `Support owner updated for ${entitlementTenantId}.`);
              }}>
                <Select
                  label="Tenant"
                  name="tenant_id"
                  value={entitlementTenantId}
                  options={internalTenantOptions}
                  onChange={setEntitlementTenantId}
                />
                <label className="full"><span>Support owner</span><input name="support_owner" placeholder="owner@customer.example" required /></label>
                <div className="form-actions full"><Button type="submit" loading={busy.startsWith('support-owner-')} disabled={!entitlementTenantId}>Assign support owner</Button></div>
              </form>
            </CardContent>
          </Card>
          <Card>
            <CardHeader>
              <CardTitle>Entitlement grants</CardTitle>
              <CardDescription>Grant or revoke plan feature entitlements for the selected tenant.</CardDescription>
            </CardHeader>
            <CardContent className="product-form">
              <Select
                label="Tenant"
                value={entitlementTenantId}
                options={internalTenantOptions}
                onChange={setEntitlementTenantId}
              />
              {effectiveEntitlements ? (
                <div className="kv-list">
                  {entitlementFeatures.map((feature) => (
                    <div key={feature}>
                      <span>{ENTITLEMENT_FEATURE_LABELS[feature] ?? feature}</span>
                      <Badge tone={effectiveEntitlements[feature] === true ? 'success' : 'muted'}>{effectiveEntitlements[feature] === true ? 'enabled' : 'disabled'}</Badge>
                    </div>
                  ))}
                </div>
              ) : <p className="muted">Effective entitlements load after tenant subscription is fetched.</p>}
              <form className="product-form" onSubmit={grantEntitlement}>
                <Select
                  label="Feature"
                  name="feature"
                  value={entitlementFeature}
                  options={entitlementFeatureOptions}
                  onChange={setEntitlementFeature}
                />
                <Select
                  label="Action"
                  name="enabled"
                  value={entitlementAction}
                  options={entitlementActionOptions}
                  onChange={setEntitlementAction}
                />
                <label className="full"><span>Reason</span><input name="reason" placeholder="Verified plan exception" required /></label>
                <div className="form-actions full"><Button type="submit" loading={busy.startsWith('entitlement-')} disabled={!entitlementTenantId}>Apply entitlement</Button></div>
              </form>
            </CardContent>
          </Card>
        </>
      )}
    </div>
  );
}
