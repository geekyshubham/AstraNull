import { Fragment, useEffect, useState, type ComponentPropsWithoutRef, type CSSProperties, type FormEvent, type HTMLAttributes, type KeyboardEvent as ReactKeyboardEvent, type MouseEvent as ReactMouseEvent, type ReactNode } from 'react';
import {
  Activity,
  Bot,
  CheckCircle2,
  CircleHelp,
  CircleMinus,
  ClipboardList,
  FileCheck2,
  FileText,
  KeyRound,
  LifeBuoy,
  ListChecks,
  Network,
  RefreshCw,
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
import { EvidenceGuide } from '../components/ui/evidence-guide';
import { emptyStateFromApi, readMetaAction } from '../lib/empty-from-api';
import { ConfirmModal, FormModal, formatMutationSuccessMessage, renderFriendlyEmptyState, useConfirmModal } from '../lib/crud-ui';
import { apiErrorMessage, humanizeErrorCode } from '../lib/error-messages';
import { Progress, type ProgressTone } from '../components/ui/progress';
import { DataTable, type TableColumn } from '../components/ui/table';
import { Select, type SelectOption } from '../components/ui/select';
import { AnchorButton, Button } from '../components/ui/button';
import { Tabs } from '../components/ui/tabs';
import { AnimatedNumber } from '../components/ui/motion';
import { runStatusTone as runStatusBadgeTone } from '../lib/status-tone';
// @ts-ignore Plain ESM keeps executive terminology directly testable with node:test.
import { dashboardReadinessMessage, plainCheckName, plainFindingTitle, plainInlineText, plainVerdictLabel } from '../lib/plain-language.mjs';
import { buildApiHeaders, requestJson } from '../lib/api';
import { canAccessRoute } from '../lib/route-access';
import { canReadDataset, sessionHasPermission, staffSessionHasPermission } from '../lib/dataset-access.mjs';
import { RoleRestrictedCard } from '../components/ui/role-restricted';
import { resolveDashboardMetrics, resolveRecentRuns } from '../lib/dashboard-metrics';
import { hasEvidenceBackedVerdict, publishedRunVerdict } from '../lib/run-verdict';
import { isFindingOpen } from '../lib/findings-helpers';
import { buildDetailHref } from '../lib/route-params';
import { DEFENSIVE_RULES, NAV_GROUP_LABELS, ROUTE_BY_ID } from '../lib/navigation';
import { routeTabs } from '../lib/prototype-manifest';
import { useDesignVariant } from '../lib/design-variant';
import { VariantSwitch } from '../components/ui/variant-switch';
import { PoliciesRefined, type PoliciesRefinedProps } from './refined/policies-refined';
import type { DataItem, PortalConfig, PortalData, ReadinessFactor, RouteId, Session } from '../lib/types';
import { countLabel, formatAuditAction, formatDate, formatNumber, formatResourceTypeLabel, formatSeverityLabel, pluralize, scoreTone } from '../lib/utils';

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

function getOptionalNumber(item: DataItem | null | undefined, keys: string[]) {
  if (!item) return null;
  for (const key of keys) {
    const value = item[key];
    if (typeof value === 'number' && Number.isFinite(value)) return value;
  }
  return null;
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
function isPolicySocGated(_policy: DataItem, _checksById: Map<string, DataItem>): boolean {
  return false;
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

function configuredSupportUri(siteConfig: Record<string, unknown>) {
  for (const key of ['support_uri', 'support_url']) {
    const candidate = typeof siteConfig[key] === 'string' ? siteConfig[key].trim() : '';
    if (!candidate) continue;
    try {
      const parsed = new URL(candidate);
      if (parsed.protocol === 'mailto:' || parsed.protocol === 'https:') return candidate;
    } catch {
      // Invalid deployment configuration is treated as unconfigured.
    }
  }
  return '';
}

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
        {/* The raw group id ("governance") leaked into the eyebrow whenever a page
            passed no explicit one; the shared label is what the breadcrumb shows. */}
        <p className="eyebrow">{eyebrow ?? (item ? NAV_GROUP_LABELS[item.group] : undefined)}</p>
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

/**
 * Count a KPI toward its value when the surface already resolved to a plain
 * grouped integer. Ratios, dashes, dates, and every other composed value are
 * rendered untouched, and the settled text is byte-identical to a static render.
 */
function KpiValue({ value }: { value: ReactNode }) {
  if (typeof value !== 'string') return <>{value}</>;
  const digits = value.replace(/,/g, '');
  if (!/^\d{1,9}$/.test(digits)) return <>{value}</>;
  const parsed = Number(digits);
  if (formatNumber(parsed) !== value) return <>{value}</>;
  return <AnimatedNumber value={parsed} />;
}

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
      <div className="kpi-value"><KpiValue value={value} /></div>
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

function businessServiceRows(data: PortalData) {
  return data.targetGroups
    .filter((group) => group.archived_at == null)
    .map((group) => {
      const groupId = getString(group, ['id'], '');
      const openFindings = data.findings.filter((finding) =>
        getString(finding, ['target_group_id']) === groupId &&
        isFindingOpen(finding)
      ).length;
      const evidenceBackedRuns = data.runs.filter((run) =>
        getString(run, ['target_group_id']) === groupId &&
        hasEvidenceBackedVerdict(run, data.evidence)
      ).length;
      return {
        group,
        groupId,
        openFindings,
        evidenceBackedRuns
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

function targetDisplayName(data: PortalData, targetId: string, fallback = '') {
  const target = data.targets.find((item) => getString(item, ['id', 'target_id'], '') === targetId);
  return getString(target ?? {}, ['hostname', 'value', 'name', 'label'], fallback || targetId || 'Target not reported');
}

function checkDisplayName(data: PortalData, checkId: string) {
  const check = data.checks.find((item) => getString(item, ['check_id', 'id'], '') === checkId);
  return plainCheckName(getString(check ?? {}, ['name', 'title'], checkId || 'Unnamed check'));
}

function runDisplayLabel(data: PortalData, run: DataItem) {
  const checkName = checkDisplayName(data, getString(run, ['check_id']));
  const targetId = getString(run, ['target_id'], '');
  const embeddedTarget = getString(run, ['target_hostname', 'target_value'], '');
  const targetName = targetDisplayName(data, targetId, embeddedTarget)
    || targetGroupDisplayName(data, getString(run, ['target_group_id']));
  return `${checkName} · ${targetName}`;
}

function evidenceDisplayLabel(item: DataItem) {
  return getString(item, ['title', 'label'], '') || getString(item, ['kind', 'type'], 'Evidence record');
}

function highScaleRequestLabel(data: PortalData, request: DataItem) {
  const objective = getString(request, ['objective', 'reason'], '').trim();
  if (objective) return objective;
  return targetGroupDisplayName(data, getString(request, ['target_group_id']));
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
  const [showCreateMoreOptions, setShowCreateMoreOptions] = useState(false);
  const [busy, setBusy] = useState('');
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');
  const canWriteTargetGroups = sessionHasPermission(session, 'target_group:write');
  const filteredGroups = data.targetGroups;
  const addTargetGroup = data.targetGroups.find((group) => getString(group, ['id'], '') === addTargetGroupId) ?? data.targetGroups[0] ?? null;
  const effectiveGroupId = getString(addTargetGroup ?? {}, ['id'], addTargetGroupId);
  const activeFilteredGroups = filteredGroups.filter((group) => group.archived_at == null && group.deleted_at == null);
  const targetCountValues = activeFilteredGroups.map((group) => getOptionalNumber(group, ['target_count', 'targets_count']));
  const declaredTargetCount = targetCountValues.every((value) => value !== null)
    ? targetCountValues.reduce<number>((sum, value) => sum + (value ?? 0), 0)
    : null;
  const openTargetFindingCount = data.findings.filter((finding) => isFindingOpen(finding)).length;
  const evidenceBackedRunCount = data.runs.filter((run) => hasEvidenceBackedVerdict(run, data.evidence)).length;

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
      .filter((run) => hasEvidenceBackedVerdict(run, data.evidence))
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
      key: 'criticality',
      label: 'Criticality',
      render: (item) => {
        const value = getString(item, ['criticality', 'business_criticality'], '');
        if (!value || value === '—') return <span className="muted">—</span>;
        const label = value.charAt(0).toUpperCase() + value.slice(1);
        return <Badge tone="muted">{label}</Badge>;
      }
    },
    {
      key: 'ownership',
      label: 'Ownership proof',
      render: (item) => {
        const state = getString(item, ['ownership_status', 'verification_status'], '');
        if (!state) return <span className="muted">Per target</span>;
        const normalized = state.toLowerCase();
        return <Badge tone={['verified', 'dns_verified', 'approved'].includes(normalized) ? 'success' : normalized.includes('fail') ? 'danger' : 'warn'}>{state.replaceAll('_', ' ')}</Badge>;
      }
    },
    {
      key: 'targets',
      label: 'Targets',
      render: (item) => {
        const count = getOptionalNumber(item, ['target_count', 'targets_count']);
        return count === null ? <span className="muted">—</span> : formatNumber(count);
      }
    },
    {
      key: 'runs',
      label: 'Runs',
      render: (item) => {
        if (data.loadErrors.runs) return <span className="muted">—</span>;
        const groupId = getString(item, ['id'], '');
        const runCount = data.runs.filter((run) => getString(run, ['target_group_id']) === groupId).length;
        return <span className="num">{formatNumber(runCount)}</span>;
      }
    },
    {
      key: 'open',
      label: 'Open',
      render: (item) => {
        if (data.loadErrors.findings) return <span className="muted">—</span>;
        const groupId = getString(item, ['id'], '');
        const open = groupStatsById.get(groupId)?.openFindings ?? 0;
        if (open === 0) return <Badge tone="success">0</Badge>;
        return <Badge tone="muted">{formatNumber(open)}</Badge>;
      }
    },
    {
      key: 'last_verdict',
      label: 'Last verdict',
      render: (item) => {
        if (data.loadErrors.runs) return <Badge tone="muted">Unavailable</Badge>;
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
    if (!canWriteTargetGroups) return;
    const formElement = event.currentTarget;
    const form = new FormData(formElement);
    const name = String(form.get('name') ?? '').trim();
    if (!name) {
      setError('Target group name is required.');
      return;
    }
    const created = await runTargetAction('create-target-group', () => requestJson(config, session, '/v1/target-groups', {
      method: 'POST',
      body: {
        name,
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
    if (!canWriteTargetGroups) return;
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
        title="Target groups"
        eyebrow="Customer-declared scope"
        description="Declare the services AstraNull validates. Ownership stays exact-target proof; AstraNull never scans the estate or requires cloud credentials."
        actions={canWriteTargetGroups ? (
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
        ) : undefined}
      />
      <div className="kpi-row" aria-label="Declared target group summary">
        <KpiCell label="Active groups" value={data.loadErrors.targetGroups ? '—' : formatNumber(activeFilteredGroups.length)} delta="Customer-declared scope" />
        <KpiCell label="Declared targets" value={data.loadErrors.targetGroups || declaredTargetCount === null ? '—' : formatNumber(declaredTargetCount)} delta={declaredTargetCount === null ? 'Count not returned for every group' : 'Exact targets only'} />
        <KpiCell label="Evidence-backed runs" value={data.loadErrors.runs ? '—' : formatNumber(evidenceBackedRunCount)} delta={data.loadErrors.runs ? 'Run data unavailable' : 'External probe verdicts'} />
        <KpiCell label="Open findings" value={data.loadErrors.findings ? '—' : formatNumber(openTargetFindingCount)} delta={data.loadErrors.findings ? 'Finding data unavailable' : 'Across declared groups'} />
      </div>
      {(message || error) && (
        <div className={error ? 'form-banner error' : 'form-banner'}>{error || message}</div>
      )}
      <Card>
        <CardHeader>
          <CardTitle>Declared target groups</CardTitle>
          <CardDescription>
            Customer-declared scope with ownership proof and the latest
            recorded verdict. Open any row for its targets, checks, and evidence.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <DataTable
            columns={groupColumns}
            items={filteredGroups}
            loadError={data.loadErrors.targetGroups}
            onRetry={() => void onRefresh()}
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
        open={canWriteTargetGroups && showCreateGroup}
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
        open={canWriteTargetGroups && showAddTarget}
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
  const canCreateReport = sessionHasPermission(session, 'report:create');
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
    if (!canCreateReport) return;
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

  const previewVerificationStatus = preview?.verification
    ? getString(preview.verification, ['status', 'result'], preview.verification.valid === true ? 'verified' : preview.verification.valid === false ? 'failed' : 'recorded')
    : 'not requested';
  const previewVerificationPassed = preview?.verification?.valid === true
    || ['verified', 'valid', 'passed'].includes(previewVerificationStatus.toLowerCase());

  return (
    <div className="content">
      <PageHeader
        route="reports"
        eyebrow="Readiness · on the record"
        description="Generate tenant-scoped readiness artifacts, verify JSON custody, and preserve export provenance for executive, technical, SOC, and audit review."
        actions={canCreateReport ? <Button type="submit" form="report-generation-form" size="sm" loading={busy === 'create-report'} disabled={busy.startsWith('export-')}>Generate &amp; export</Button> : undefined}
      />
      <PageContextSummary>
        <span className="tabular-nums">{data.loadErrors.reports ? '—' : formatNumber(reports.length)}</span> reports
        {canReadDataset(session, 'audit') ? (
          <>
            {' · '}<span className="tabular-nums">{data.loadErrors.audit ? '—' : formatNumber(reportExports)}</span> custody exports recorded
          </>
        ) : null}
      </PageContextSummary>
      {(message || error) && <div className={error ? 'form-banner error' : 'form-banner'} role={error ? 'alert' : 'status'}>{error || message}</div>}
      {preview ? (
        <Card className="card--dense">
          <PanelCardHeader
            title="Latest export custody"
            description={`${preview.title} · ${preview.format.toUpperCase()}`}
            trailing={<Badge tone={previewVerificationPassed ? 'success' : preview.verification ? 'warn' : 'muted'}>{previewVerificationStatus.replaceAll('_', ' ')}</Badge>}
          />
          <CardContent>
            {preview.textPreview ? (
              <pre className="codeblock" tabIndex={0} aria-label="Export text preview">{preview.textPreview}</pre>
            ) : (
              <div className="kv-list">
                <div><span>Report</span><strong className="mono">{preview.reportId}</strong></div>
                <div><span>Artifact</span><strong className="mono">{preview.artifactId || 'Not returned'}</strong></div>
                <div><span>Schema</span><strong className="mono">{preview.schemaVersion || 'Not returned'}</strong></div>
                <div><span>SHA-256</span><strong className="mono">{preview.contentSha256 || 'Not returned'}</strong></div>
              </div>
            )}
          </CardContent>
        </Card>
      ) : null}
      <Card>
        <CardHeader>
          <CardTitle>Generate report</CardTitle>
          <CardDescription>Select kind, export format, and period. JSON exports are verified against their returned custody envelope before the preview is marked verified.</CardDescription>
        </CardHeader>
        <CardContent>
          {canCreateReport ? (
            <form id="report-generation-form" className="product-form" onSubmit={handleCreateReport} aria-busy={busy === 'create-report' || undefined}>
              <Select label="Kind" name="kind" value={selectedReportKind} options={reportKindOptions} onChange={setReportKind} />
              <Select label="Format" name="format" value={selectedReportFormat} options={reportFormatOptions} onChange={setReportFormat} />
              <Select label="Period" name="period" value={selectedReportPeriod} options={reportPeriodOptions} onChange={setReportPeriod} />
              <p className="muted text-xs full">Direct PDF export is not available. Export HTML, then save it as PDF in your review tool.</p>
            </form>
          ) : <RoleRestrictedCard title="Report generation is not available for your role." />}
        </CardContent>
      </Card>
      <Card className="card--dense">
        <PanelCardHeader title="Recent reports" description="Open a report to inspect its scope, evidence summary, and available custody exports." />
        <CardContent aria-busy={busy.startsWith('export-') || busy === 'create-report' || undefined}>
          <DataTable
            columns={reportColumns}
            items={reports}
            loadError={data.loadErrors.reports}
            onRetry={() => void onRefresh()}
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
  const { confirm } = useConfirmModal();
  const [tab, setTab] = useState<SettingsTab>('organization');
  const [busy, setBusy] = useState('');
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');
  const [oneTimeSecret, setOneTimeSecret] = useState<{ label: string; value: string } | null>(null);
  const [rotateSecretId, setRotateSecretId] = useState('');
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
  const privacy = getNestedItem(tenant, ['privacy_settings']) ?? {};
  const evidenceRetention = getNestedItem(privacy, ['evidence_retention']) ?? {};
  const recordedMetadataRetentionDays = getOptionalNumber(privacy, ['metadata_retention_days']);
  const metadataRetentionDays = recordedMetadataRetentionDays ?? 90;
  const oidcPosture = readOidcPosture(config);
  const routeAccessContext = {
    principal: session.principal,
    staffRole: session.staff_role,
  };
  const role = session.role ?? 'admin';
  const canReadAudit = canAccessRoute(role, 'audit', routeAccessContext);
  const canReadNotifications = canAccessRoute(role, 'notifications', routeAccessContext);
  const canReadSecrets = canReadDataset(session, 'secrets');
  const canReadServiceAccounts = canReadDataset(session, 'serviceAccounts');
  const canCreateServiceAccount = sessionHasPermission(session, 'service_account:create');
  const canRevokeServiceAccount = sessionHasPermission(session, 'service_account:revoke');
  const canRotateServiceAccount = sessionHasPermission(session, 'service_account:rotate');
  const canWriteTenant = sessionHasPermission(session, 'tenant:write');
  const canWriteSecrets = sessionHasPermission(session, 'secret:write');
  const canRotateSecrets = sessionHasPermission(session, 'secret:rotate');
  const settingsTabOptions = SETTINGS_TAB_OPTIONS;
  const serviceAccountColumns: TableColumn<DataItem>[] = [
    { key: 'name', label: 'Account', render: (item) => getString(item, ['name', 'id']) },
    { key: 'role', label: 'Role', render: (item) => <Badge tone="muted">{getString(item, ['role'])}</Badge> },
    { key: 'scopes', label: 'Scopes', render: (item) => Array.isArray(item.scopes) ? item.scopes.join(', ') : 'Not recorded' },
    { key: 'expires', label: 'Expires', render: (item) => item.expires_at ? formatDate(item.expires_at) : 'No expiry' },
    { key: 'state', label: 'State', render: (item) => <Badge tone={item.revoked_at ? 'muted' : 'success'}>{item.revoked_at ? 'revoked' : 'active'}</Badge> },
    {
      key: 'actions',
      label: 'Actions',
      render: (item) => {
        const id = getString(item, ['id'], '');
        if (!canRotateServiceAccount && !canRevokeServiceAccount) return <span className="muted">Read only</span>;
        return (
          <div className="row-actions">
            {canRotateServiceAccount ? <Button size="sm" variant="secondary" disabled={busy !== '' || Boolean(item.revoked_at)} onClick={() => void rotateServiceAccount(id)}>Rotate</Button> : null}
            {canRevokeServiceAccount ? <Button size="sm" variant="danger" disabled={busy !== '' || Boolean(item.revoked_at)} onClick={() => void revokeServiceAccount(id)}>Revoke</Button> : null}
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

  async function handleCreateServiceAccount(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!canCreateServiceAccount) return;
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
    }), 'Service account created. Copy its secret now; it is shown once.');
    if (result && typeof result === 'object' && 'secret' in result && typeof (result as { secret?: unknown }).secret === 'string') {
      setOneTimeSecret({ label: 'Service account secret', value: String((result as { secret: string }).secret) });
      formElement.reset();
    }
  }

  async function revokeServiceAccount(id: string) {
    if (!canRevokeServiceAccount || !id) return;
    if (!await confirm({ title: 'Revoke service account', description: 'Revoke this service account? Automated access using its secret will stop working.', confirmLabel: 'Revoke account' })) return;
    await runSettingsAction(`revoke-service-${id}`, () => requestJson(config, session, `/v1/service-accounts/${id}/revoke`, { method: 'POST' }), 'Service account revoked.');
  }

  async function rotateServiceAccount(id: string) {
    if (!canRotateServiceAccount || !id) return;
    if (!await confirm({ title: 'Rotate service account secret', description: 'Rotate this service account? The current secret will stop working immediately.', confirmLabel: 'Rotate secret' })) return;
    const result = await runSettingsAction(`rotate-service-${id}`, () => requestJson(config, session, `/v1/service-accounts/${id}/rotate`, { method: 'POST' }), 'Service account rotated. Copy the new secret now; it is shown once.');
    if (result && typeof result === 'object' && 'secret' in result && typeof (result as { secret?: unknown }).secret === 'string') {
      setOneTimeSecret({ label: 'Rotated service account secret', value: String((result as { secret: string }).secret) });
    }
  }

  async function handleSaveOrganization(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!canWriteTenant) return;
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
    if (!canWriteTenant) return;
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
    if (!canWriteTenant) return;
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
    if (!canWriteSecrets) return;
    const formElement = event.currentTarget;
    const form = new FormData(formElement);
    const purpose = String(form.get('purpose') ?? '').trim();
    const name = String(form.get('name') ?? '').trim();
    const plaintext = String(form.get('plaintext') ?? '').trim();
    if (!purpose || !name || !plaintext) {
      setError('Purpose, name, and credential value are required.');
      return;
    }
    if (!await confirm({ title: 'Store integration secret', description: 'Store this integration secret? Authorized internal workflows will use the new credential.', confirmLabel: 'Store secret', confirmTone: 'default' })) return;
    await runSettingsAction('create-vault-secret', () => requestJson(config, session, '/v1/secrets', {
      method: 'POST',
      body: {
        purpose,
        name,
        plaintext,
        metadata: { source: 'settings_vault' }
      }
    }), 'Integration secret stored. Plaintext never appears in list views.');
    formElement.reset();
  }

  async function handleRotateVaultSecret(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!canRotateSecrets) return;
    const formElement = event.currentTarget;
    const form = new FormData(formElement);
    const id = String(form.get('secret_id') ?? rotateSecretId).trim();
    const plaintext = String(form.get('plaintext') ?? '').trim();
    if (!id || !plaintext) {
      setError('Select a secret and provide the replacement credential value.');
      return;
    }
    if (!await confirm({ title: 'Rotate vault secret', description: 'Rotate this vault secret? The current credential will stop working for authorized internal workflows.', confirmLabel: 'Rotate secret' })) return;
    await runSettingsAction(`rotate-vault-${id}`, () => requestJson(config, session, `/v1/secrets/${id}/rotate`, {
      method: 'POST',
      body: { plaintext }
    }), 'Secret rotated. Prior credential stops working for authorized internal workflows.');
    formElement.reset();
    setRotateSecretId('');
  }

  const secretColumns: TableColumn<DataItem>[] = [
    { key: 'name', label: 'Name', render: (item) => getString(item, ['name', 'id']) },
    { key: 'purpose', label: 'Purpose', render: (item) => <Badge tone="muted">{getString(item, ['purpose'])}</Badge> },
    { key: 'rotation', label: 'Rotation', render: (item) => getOptionalNumber(item, ['rotation']) ?? <span className="muted">—</span> },
    { key: 'updated', label: 'Updated', render: (item) => formatDate(item.updated_at ?? item.created_at) },
    {
      key: 'actions',
      label: 'Actions',
      render: (item) => {
        const id = getString(item, ['id'], '');
        if (!canRotateSecrets) return <span className="muted">Read only</span>;
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
        description="Manage organization identity, one-time credentials, secret metadata, and retention while platform safety boundaries remain enforced."
      />
      <PageContextSummary>
        {getString(tenant ?? {}, ['name'], 'Organization')} ·{' '}
        {canReadSecrets ? (
          <><span className="tabular-nums">{data.loadErrors.secrets ? '—' : formatNumber(data.secrets.length)}</span> vault secrets ·{' '}</>
        ) : null}
        <span className="tabular-nums">{recordedMetadataRetentionDays === null ? 'not recorded' : `${recordedMetadataRetentionDays}d`}</span> metadata retention
      </PageContextSummary>
      <Tabs value={tab} options={settingsTabOptions} onChange={setTab} className="tabs-wrap" ariaLabel="Settings sections"
            getTabId={(id) => `settings-sections-tab-${id}`}
            getPanelId={(id) => `settings-sections-panel-${id}`} />
      {(message || error) && (
        <div className={error ? 'form-banner error' : 'form-banner'}>
          {error || message}
        </div>
      )}
      {oneTimeSecret && (
        <Card className="secret-card">
          <PanelCardHeader
            title={oneTimeSecret.label}
            description="This value is shown once and will not be visible after refresh."
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
        <div role="tabpanel" id="settings-sections-panel-organization" aria-labelledby="settings-sections-tab-organization" className="tab-panel"><>
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
                    <input name="name" defaultValue={getString(tenant, ['name'])} required readOnly={!canWriteTenant} />
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
                    {canWriteTenant
                      ? <Button type="submit" loading={busy === 'save-organization'}>Save organization</Button>
                      : <span className="muted">Organization settings are read-only for your role.</span>}
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
              <div><span>Target groups</span><strong>{data.loadErrors.targetGroups ? '—' : formatNumber(data.targetGroups.length)}</strong></div>
              <div><span>Evidence records</span><strong>{data.loadErrors.evidence ? '—' : formatNumber(data.evidence.length)}</strong></div>
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
            <SettingsNote icon={FileCheck2}>Automation credentials live under Access; vault secrets under Security; audit history on the Audit page.</SettingsNote>
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
        </></div>
      )}

      {tab === 'access' && (
        <div role="tabpanel" id="settings-sections-panel-access" aria-labelledby="settings-sections-tab-access" className="tab-panel"><>
          {canCreateServiceAccount ? (
          <div className="split">
            {canCreateServiceAccount ? (
            <Card>
              <CardHeader>
                <CardTitle>Create service account</CardTitle>
                <CardDescription>Create scoped automation credentials. Secrets are shown once and list views stay redacted.</CardDescription>
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
                    <Button type="submit" loading={busy === 'create-service-account'}>Create service account</Button>
                  </div>
                </form>
              </CardContent>
            </Card>
            ) : null}
          </div>
          ) : null}
          {canReadServiceAccounts ? (
          <Card>
            <PanelCardHeader
              title="Service accounts"
              description="Automation credentials are scoped, auditable, rotatable, and redacted after creation."
              trailing={<Badge tone="muted">{data.serviceAccounts.length} records</Badge>}
            />
            <CardContent>
              <DataTable
                columns={serviceAccountColumns}
                items={data.serviceAccounts}
                empty={<EmptyState icon={UserCog} title="No service accounts." body="Create a service account only for a clear automation owner and scope." />}
                loadError={data.loadErrors.serviceAccounts}
                onRetry={onRefresh ? () => void onRefresh() : undefined}
              />
            </CardContent>
          </Card>
          ) : <RoleRestrictedCard title="Service accounts are not available for your role." />}
        </></div>
      )}

      {tab === 'security' && (
        <div role="tabpanel" id="settings-sections-panel-security" aria-labelledby="settings-sections-tab-security" className="tab-panel"><>
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
          {canWriteSecrets || (canRotateSecrets && canReadSecrets) ? (
          <div className="split">
            {canWriteSecrets ? (
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
                      <option value="provider_api">Provider service</option>
                    </select>
                  </label>
                  <label>
                    <span>Name</span>
                    <input name="name" placeholder="cloudflare:edge-readonly" required />
                  </label>
                  <label className="full">
                    <span>Credential value</span>
                    <textarea name="plaintext" rows={4} placeholder="Provider access token or JSON credential" required />
                  </label>
                  <div className="form-actions full">
                    <Button type="submit" loading={busy === 'create-vault-secret'}>Store secret</Button>
                  </div>
                </form>
              </CardContent>
            </Card>
            ) : null}
            {canRotateSecrets && canReadSecrets ? (
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
                    <textarea name="plaintext" rows={4} placeholder="New provider access token or JSON credential" required />
                  </label>
                  <div className="form-actions full">
                    <Button type="submit" disabled={busy !== '' || data.secrets.length === 0}>Rotate secret</Button>
                  </div>
                </form>
              </CardContent>
            </Card>
            ) : null}
          </div>
          ) : null}
          {canReadSecrets ? (
          <Card>
            <PanelCardHeader
              title="Secret vault inventory"
              description="Stored secret metadata only — no plaintext, ciphertext, or auth tags."
              trailing={<Badge tone="muted">{data.secrets.length} records</Badge>}
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
          ) : <RoleRestrictedCard title="Secret vault inventory is not available for your role." />}
        </></div>
      )}

      {tab === 'privacy' && (
        <div role="tabpanel" id="settings-sections-panel-privacy" aria-labelledby="settings-sections-tab-privacy" className="tab-panel"><Card>
          <CardHeader>
            <CardTitle>Privacy and retention</CardTitle>
            <CardDescription>Updates metadata and evidence retention for this tenant. Shorter windows can purge stored metadata immediately.</CardDescription>
          </CardHeader>
          <CardContent>
            {canWriteTenant ? (
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
            ) : <RoleRestrictedCard title="Retention settings are read-only for your role." />}
          </CardContent>
          <CardContent className="settings-list">
            <SettingsNote icon={FileCheck2}>Metadata retention applies to events, evidence vault, reports, and notification events for the current tenant.</SettingsNote>
            <SettingsNote icon={ShieldCheck}>Audit logs, findings, test runs, and authorization artifacts follow separate production retention gates documented in the operations guide.</SettingsNote>
          </CardContent>
        </Card></div>
      )}

      <ConfirmModal
        open={canWriteTenant && Boolean(pendingRetention)}
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
  const { confirm } = useConfirmModal();
  const [designVariant, setDesignVariant] = useDesignVariant('test-policies');
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
  const canWritePolicies = sessionHasPermission(session, 'test_policy:write');
  const safeChecks = data.checks.filter((check) => getString(check, ['safety_class']) === 'safe');
  const socGatedChecks = data.checks.filter((check) => getString(check, ['safety_class']) === 'soc_gated');
  const checksById = new Map<string, DataItem>(
    data.checks.map((check) => [getString(check, ['check_id', 'id'], ''), check])
  );
  const activePolicies = data.testPolicies.filter((policy) => !['paused', 'archived', 'deleted'].includes(getString(policy, ['state'], 'active')));
  const socScheduledCount = activePolicies.filter((policy) => isPolicySocGated(policy, checksById)).length;
  const boundPolicyCount = activePolicies.filter((policy) => Boolean(getString(policy, ['check_id'], ''))).length;
  const upcomingRuns = activePolicies
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
    { key: 'id', label: 'Schedule', render: (item) => { const policyId = getString(item, ['id', 'policy_id'], ''); return <span title={policyId || undefined}>{getString(item, ['name', 'title'], 'Scheduled policy')}</span>; } },
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
        const label = plainCheckName(getString(check, ['name', 'check_id'], checkId));
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
    {
      key: 'expected',
      label: 'Expected verdict',
      render: (item) => (
        <div className="stack-tight">
          <Badge tone={policyVerdictBadgeTone(getString(item, ['expected_verdict']))}>{formatPolicyVerdictLabel(getString(item, ['expected_verdict']))}</Badge>
          <span className="muted small">Declared expectation</span>
        </div>
      )
    },
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
        if (!canWritePolicies) return <span className="muted">Read only</span>;
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
    if (!canWritePolicies) return;
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
    if (!canWritePolicies || !id) return;
    if ('cadence' in body && body.cadence === 'weekly') {
      if (!await confirm({ title: 'Change policy cadence', description: 'Set this policy cadence to weekly? Scheduled runs will follow the weekly window.', confirmLabel: 'Set weekly', confirmTone: 'default' })) return;
    }
    if ('state' in body) {
      const pausing = body.state === 'paused';
      if (!await confirm({
        title: pausing ? 'Pause policy' : 'Resume policy',
        description: pausing ? 'Pause this policy? Scheduled runs under it will stop.' : 'Resume this policy?',
        confirmLabel: pausing ? 'Pause policy' : 'Resume policy',
        confirmTone: pausing ? 'danger' : 'default'
      })) return;
    }
    await runPolicyAction(`patch-policy-${id}`, () => requestJson(config, session, `/v1/test-policies/${id}`, {
      method: 'PATCH',
      body
    }), success);
  }

  async function archivePolicy(id: string) {
    if (!canWritePolicies || !id) return;
    await runPolicyAction(`archive-policy-${id}`, () => requestJson(config, session, `/v1/test-policies/${id}`, { method: 'DELETE' }), 'Test policy archived.');
    setArchivePolicyId('');
  }

  function getPolicyRowProps(item: DataItem) {
    const id = getString(item, ['id', 'policy_id'], '');
    if (!id) return {};
    const rowBusy = busy === `patch-policy-${id}` || busy === `archive-policy-${id}`;
    const linkProps = detailRowProps('policy-detail', id, `Open schedule ${id} detail`);
    return rowBusy ? { ...linkProps, 'aria-busy': true } : linkProps;
  }
  const policyEmptyState = renderFriendlyEmptyState({
    icon: ClipboardList,
    title: 'No schedules yet.',
    body: 'Create a validation schedule after declaring target groups and reviewing the check catalog.',
    actionLabel: canWritePolicies ? 'New schedule' : undefined,
    onAction: canWritePolicies ? () => setShowCreateSchedule(true) : undefined
  });
  const createScheduleModal = (
      <FormModal
        open={canWritePolicies && showCreateSchedule}
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
  );
  const archiveScheduleModal = (
      <ConfirmModal
        open={canWritePolicies && Boolean(archivePolicyId)}
        title={`Archive schedule ${archivePolicyId}`}
        description={<p>Are you sure? Scheduled runs under this schedule will stop and an audit entry will be written.</p>}
        confirmLabel="Archive schedule"
        busy={busy === `archive-policy-${archivePolicyId}`}
        onCancel={() => setArchivePolicyId('')}
        onConfirm={() => void archivePolicy(archivePolicyId)}
      />
  );
  const policyModals = <>{createScheduleModal}{archiveScheduleModal}</>;
  const variantSwitch = <VariantSwitch value={designVariant} onChange={setDesignVariant} />;

  if (designVariant === 'refined') {
    const refinedProps: PoliciesRefinedProps = {
      data,
      config,
      session,
      onRefresh,
      variant: designVariant,
      onVariantChange: setDesignVariant,
      busy,
      message,
      error,
      canWritePolicies,
      policyColumns,
      activePolicies,
      safeChecks,
      socGatedChecks,
      socScheduledCount,
      boundPolicyCount,
      upcomingRuns,
      nextRunLabel,
      getPolicyRowProps,
      getPolicyNextRun: (item) => {
        const socGated = isPolicySocGated(item, checksById);
        return { ...derivePolicyNextRun(item, socGated), socGated };
      },
      policyEmptyState,
      onCreateSchedule: () => setShowCreateSchedule(true),
      // Refined renders the create form inline from this model, so only the archive confirm is a modal.
      modals: archiveScheduleModal,
      createForm: {
        open: canWritePolicies && showCreateSchedule,
        onClose: () => setShowCreateSchedule(false),
        onSubmit: (event) => void handleCreatePolicy(event),
        targetGroups: activePolicyTargetGroups,
        selectedGroupIds: policyTargetGroupIds,
        onTargetGroupsChange: handlePolicyTargetGroupChange,
        bindings: policyTargetBindings,
        onSelectTarget: (targetGroupId, selectedTargetId) => setPolicyTargetBindings((current) => ({
          ...current,
          [targetGroupId]: {
            targets: current[targetGroupId]?.targets ?? [],
            selectedTargetId,
            loading: false,
            error: ''
          }
        })),
        onRetryTargets: (targetGroupId) => void loadPolicyTargetsForGroup(targetGroupId),
        bindingsReady: policyBindingsReady,
        selectedCheck: selectedPolicyCheck,
        checkId: policyCheckId,
        checkOptions: policyCheckOptions,
        onCheckChange: handlePolicyCheckChange,
        cadence: policyCadence,
        cadenceOptions: POLICY_CADENCE_OPTIONS,
        onCadenceChange: setPolicyCadence,
        expectedVerdict: policyExpectedVerdict,
        verdictOptions: POLICY_VERDICT_OPTIONS,
        onExpectedVerdictChange: setPolicyExpectedVerdict
      }
    };
    return <PoliciesRefined {...refinedProps} />;
  }

  return (
    <div className="content">
      <PageHeader
        route="test-policies"
        title="Test policies"
        eyebrow="Declared scope · bounded execution"
        description="Scheduled validation cadences, exact target bindings, and safe windows. Expected verdicts remain declarations until external probe evidence is recorded; high-scale scenarios stay SOC-scheduled."
        actions={(
          <>
            {variantSwitch}
            {canWritePolicies ? (
              <Button
                variant="default"
                size="sm"
                disabled={busy !== ''}
                onClick={() => setShowCreateSchedule(true)}
              >
                Create schedule
              </Button>
            ) : null}
          </>
        )}
      />
      <div className="kpi-row">
        <KpiCell
          label="Active schedules"
          value={data.loadErrors.testPolicies ? '—' : formatNumber(activePolicies.length)}
          delta={data.loadErrors.checks ? 'Check catalog unavailable' : `${safeChecks.length} checks bindable`}
        />
        <KpiCell
          label="Next run"
          value={data.loadErrors.testPolicies ? '—' : nextRunLabel}
          delta={data.loadErrors.testPolicies ? 'Policy data unavailable' : upcomingRuns.length > 0 ? `${upcomingRuns.length} upcoming` : 'No cadence scheduled'}
        />
        <KpiCell label="Checks bound" value={data.loadErrors.testPolicies ? '—' : formatNumber(boundPolicyCount)} delta="Exact schedule bindings" />
        <KpiCell
          label="SOC-scheduled"
          value={data.loadErrors.testPolicies || data.loadErrors.checks ? '—' : formatNumber(socScheduledCount)}
          delta={data.loadErrors.testPolicies || data.loadErrors.checks ? 'SOC schedule data unavailable' : socScheduledCount > 0 ? 'Awaiting SOC' : 'None gated'}
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
                {activePolicies.length} active · {data.testPolicies.length} total · {safeChecks.length} checks
              </span>
            </>
          }
          trailing={data.testPolicies.length > 0 ? <Badge tone="info">{activePolicies.length} active</Badge> : undefined}
        />
        <CardContent>
          <DataTable
            columns={policyColumns}
            items={data.testPolicies}
            loadError={data.loadErrors.testPolicies}
            onRetry={() => void onRefresh()}
            getRowId={(item) => getString(item, ['id', 'policy_id'], '')}
            getRowProps={getPolicyRowProps}
            empty={policyEmptyState}
          />
        </CardContent>
      </Card>
      {policyModals}
    </div>
  );
}

export function SupportPage({ data, session, config }: { data: PortalData; session: Session; config: PortalConfig }) {
  const summary = data.subscriptionSummary;
  const supportUri = configuredSupportUri(config.siteConfig);
  const support = getNestedItem(summary, ['support']);
  const usage = getNestedItem(summary, ['usage']);
  const account = getNestedItem(summary, ['account']);
  const recentAudit = getNestedArray(support, ['recent_audit']);
  const openFindings = getOptionalNumber(usage, ['open_findings']);
  const pendingHighScale = getOptionalNumber(usage, ['pending_high_scale_requests']);
  const auditEvents = getOptionalNumber(usage, ['audit_events']);
  const supportOwner = getString(support ?? {}, ['owner'], 'Unassigned');
  const escalationState = getString(support ?? {}, ['escalation_state'], summary ? 'nominal' : 'No record');
  const supportLoadError = data.loadErrors.subscriptionSummary;
  const routeAccessContext = { principal: session.principal, staffRole: session.staff_role };
  const role = session.role ?? 'admin';
  const canReadNotifications = canAccessRoute(role, 'notifications', routeAccessContext);
  const openFindingsLabel = openFindings === null ? 'not recorded' : formatNumber(openFindings);
  const pendingHighScaleLabel = pendingHighScale === null ? 'not recorded' : formatNumber(pendingHighScale);
  const supportRows = summary ? [
    { label: 'Support owner', value: supportOwner, icon: LifeBuoy },
    { label: 'Account lifecycle', value: getString(account ?? support ?? {}, ['lifecycle_state'], 'unrecorded'), icon: ShieldCheck },
    { label: 'Region', value: getString(account ?? support ?? {}, ['region'], 'unrecorded'), icon: Network },
    { label: 'Recent tenant audit records', value: auditEvents === null ? 'Not recorded' : formatNumber(auditEvents), icon: FileCheck2 }
  ] : [];

  return (
    <div className="content">
      <PageHeader
        route="support"
        eyebrow="Readiness support"
        description="Account ownership, escalation context, and recent audit evidence inside AstraNull's defensive validation boundaries."
        actions={supportUri ? <AnchorButton href={supportUri} variant="default" size="sm">Contact support</AnchorButton> : undefined}
      />
      <PageContextSummary>
        Owner {summary ? supportOwner : '—'} · <span className="tabular-nums">{summary ? openFindingsLabel : '—'}</span> open findings · <span className="tabular-nums">{summary ? pendingHighScaleLabel : '—'}</span> SOC escalations{summary ? ` (${escalationState.replaceAll('_', ' ')})` : ''}
      </PageContextSummary>
      {!supportUri ? (
        <div className="form-banner info" role="status">
          This deployment has not configured a support contact channel. Use the in-product evidence and SOC workflows below until an administrator provides one.
        </div>
      ) : null}
      {supportLoadError ? <div className="form-banner error row-actions" role="alert"><span>{supportLoadError} Previously loaded support context may be stale.</span><Button type="button" size="sm" variant="secondary" onClick={() => window.location.reload()}>Retry</Button></div> : null}
      <div className="split">
        <Card>
          <CardHeader><CardTitle>Support readiness</CardTitle><CardDescription>Tenant support posture from account, findings, high-scale, and audit records.</CardDescription></CardHeader>
          <CardContent className="settings-list">
            {supportRows.length === 0 ? <EmptyState icon={LifeBuoy} title="No support account record." body="Approve a signup request or attach tenant account metadata before support readiness can show live ownership." /> : supportRows.map(({ label, value, icon: RowIcon }) => (
              <div key={label}><RowIcon size={18} aria-hidden /><span><strong>{label}</strong>{' — '}{label === 'Account lifecycle' ? <Badge tone={lifecycleBadgeTone(value)}>{value}</Badge> : value}</span></div>
            ))}
          </CardContent>
        </Card>
        <Card>
          <CardHeader><CardTitle>Recent support evidence</CardTitle><CardDescription>Latest tenant audit events exposed as metadata-only support context.</CardDescription></CardHeader>
          <CardContent className="queue-list support-evidence-list">
            {recentAudit.length === 0 ? <EmptyState icon={FileCheck2} title="No recent support evidence." body="Tenant audit entries will appear here after support-relevant actions are recorded." /> : recentAudit.map((entry) => {
              const action = getString(entry, ['action'], '—');
              const resourceType = getString(entry, ['resource_type'], 'audit');
              return <div key={getString(entry, ['id', 'created_at', 'action'])} className="support-evidence-item"><div className="support-evidence-main"><span className="support-evidence-type">{formatResourceTypeLabel(resourceType)}</span><span className="support-evidence-action">{formatAuditAction(action, action)}</span></div><div className="support-evidence-meta"><span className="muted">{formatDate(entry.created_at)}</span><AnchorButton size="sm" variant="ghost" href="#audit">View</AnchorButton></div></div>;
            })}
          </CardContent>
        </Card>
      </div>
      <Card>
        <CardHeader><CardTitle>Support workflows</CardTitle><CardDescription>Customer escalation paths within authorized validation boundaries.</CardDescription></CardHeader>
        <CardContent className="stack">
          <CalloutNote icon={Siren} tone="warn">Support can coordinate escalation and request a stop. Only SOC can approve, schedule, execute, or stop high-scale validation; customer stop authority remains binding.</CalloutNote>
          <div className="row-actions">
            <AnchorButton href="#findings" variant="secondary" size="sm">Review open findings ({openFindingsLabel})</AnchorButton>
            <AnchorButton href="#runs" variant="secondary" size="sm">Request SOC-governed test ({pendingHighScaleLabel} pending)</AnchorButton>
            {canReadNotifications ? <AnchorButton href="#notifications" variant="secondary" size="sm">Notification rules</AnchorButton> : null}
          </div>
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
  gap: 1px;
  overflow: hidden;
  border: 1px solid var(--border-soft);
  border-radius: var(--radius-md);
  background: var(--border-soft);
}
.subscription-page .subscription-usage-card {
  display: flex;
  min-width: 0;
  flex-direction: column;
  gap: var(--space-3);
  padding: var(--space-4);
  border: 0;
  border-radius: 0;
  background: var(--surface);
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
          body="No subscription record is available. Contact AstraNull support for provisioning or billing assistance."
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
          description="Each metric joins the recorded count, authoritative limit, and progress state."
          trailing={<Badge tone="muted">{recordedUsageCount} / {usageRows.length} recorded</Badge>}
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
            <EmptyState icon={Activity} title="No usage snapshot recorded." body="Plan details are available, but workspace usage counts were not recorded." />
          )}
        </CardContent>
      </Card>

      <Card className="card--dense">
        <PanelCardHeader
          title="Effective entitlements"
          description="Effective access is the recorded subscription decision. Plan inclusion and access source explain how it was derived."
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
  const { confirm } = useConfirmModal();
  const [busy, setBusy] = useState('');
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');
  const [entitlementTenantId, setEntitlementTenantId] = useState(() => getString(data.internalTenants[0] ?? {}, ['tenant_id', 'id'], ''));
  const [entitlementFeature, setEntitlementFeature] = useState('waf_posture');
  const [entitlementAction, setEntitlementAction] = useState('true');
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
  const [adminTab, setAdminTab] = useState('overview');
  const canReadSignups = canReadDataset(session, 'internalSignupRequests');
  const canReadTenants = canReadDataset(session, 'internalTenants');
  const canReadApprovals = canReadDataset(session, 'internalApprovalRequests');
  const canReadInternalAudit = canReadDataset(session, 'internalAudit');
  const canDecideSignups = staffSessionHasPermission(session, 'staff:signup:decide');
  const canDecideApprovals = staffSessionHasPermission(session, 'staff:approval:decide');
  const canWriteTenants = staffSessionHasPermission(session, 'staff:tenant:write');
  const canWriteEntitlements = staffSessionHasPermission(session, 'staff:entitlement:write');
  const adminTabReadable: Record<string, boolean> = {
    'signup-queue': canReadSignups,
    tenants: canReadTenants,
    approvals: canReadApprovals,
    audit: canReadInternalAudit
  };
  const adminTabOptions = routeTabs('admin')
    .filter((tab) => adminTabReadable[tab.id] ?? true)
    .map((tab) => ({ id: tab.id, label: tab.label }));
  const activeAdminTab = adminTabOptions.some((tab) => tab.id === adminTab) ? adminTab : 'overview';
  const overview = data.internalOverview;
  const pendingSignups = !canReadSignups ? 0 : data.loadErrors.internalSignupRequests ? null : getOptionalNumber(overview, ['pending_signups']) ?? data.internalSignupRequests.filter((item) => ['submitted', 'under_review'].includes(getString(item, ['state'], ''))).length;
  const pendingApprovals = !canReadApprovals ? 0 : data.loadErrors.internalApprovalRequests ? null : getOptionalNumber(overview, ['pending_approval_requests']) ?? data.internalApprovalRequests.filter((item) => ['submitted', 'under_review'].includes(getString(item, ['state'], ''))).length;
  const queueDepth = pendingSignups === null || pendingApprovals === null ? null : pendingSignups + pendingApprovals;
  const tenantCount = !canReadTenants ? null : getOptionalNumber(overview, ['tenant_count']) ?? (data.loadErrors.internalTenants ? null : data.internalTenants.length);
  const highScaleReviews = !canReadApprovals ? null : getOptionalNumber(overview, ['high_scale_reviews']) ?? (data.loadErrors.internalApprovalRequests ? null : data.internalApprovalRequests.filter((item) => getString(item, ['kind'], '').includes('high_scale') && ['submitted', 'under_review'].includes(getString(item, ['state'], ''))).length);
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
    if (!await confirm({ title: 'Approve signup request', description: 'Approve this signup request? A tenant account will be provisioned.', confirmLabel: 'Approve request', confirmTone: 'default' })) return;
    await runStaffAction(`approve-signup-${id}`, () => requestJson(config, session, `/internal/admin/signup-requests/${id}/approve`, {
      method: 'POST',
      body: { reason: 'Approved from React staff console.' }
    }), 'Signup request approved and tenant provisioned.');
  }

  async function rejectSignup(id: string) {
    if (!await confirm({ title: 'Reject signup request', description: 'Reject this signup request? No tenant will be provisioned for this applicant.', confirmLabel: 'Reject request' })) return;
    await runStaffAction(`reject-signup-${id}`, () => requestJson(config, session, `/internal/admin/signup-requests/${id}/reject`, {
      method: 'POST',
      body: { reason: 'Rejected from React staff console.' }
    }), 'Signup request rejected.');
  }

  async function decideApproval(id: string, decision: 'approve' | 'reject') {
    if (decision === 'approve') {
      if (!await confirm({ title: 'Approve internal request', description: 'Approve this internal approval request? The requested action will proceed.', confirmLabel: 'Approve request', confirmTone: 'default' })) return;
    } else if (!await confirm({ title: 'Reject internal request', description: 'Reject this internal approval request? The requested action will not proceed.', confirmLabel: 'Reject request' })) return;
    await runStaffAction(`approval-${id}-${decision}`, () => requestJson(config, session, `/internal/admin/approval-requests/${id}/decision`, {
      method: 'POST',
      body: { decision, reason: `${decision} from React staff console.` }
    }), `Approval request ${decision}d.`);
  }

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
      if (!await confirm({ title: 'Grant tenant entitlement', description: `Grant the ${featureLabel} entitlement for this tenant?`, confirmLabel: 'Grant entitlement', confirmTone: 'default' })) return;
    } else if (!await confirm({ title: 'Revoke tenant entitlement', description: `Revoke the ${featureLabel} entitlement? The feature will be disabled for this tenant.`, confirmLabel: 'Revoke entitlement' })) return;
    await runStaffAction(`entitlement-${entitlementTenantId}-${feature}`, () => requestJson(config, session, `/internal/admin/tenants/${encodeURIComponent(entitlementTenantId)}/entitlements`, {
      method: 'POST',
      body: { feature, enabled, reason: reason || `Entitlement ${enabled ? 'granted' : 'revoked'} from React staff console.` }
    }), `${feature} entitlement ${enabled ? 'granted' : 'revoked'} for ${entitlementTenantId}.`);
  }

  const selectedEntitlementTenant = data.internalTenants.find(
    (tenant) => getString(tenant, ['tenant_id', 'id'], '') === entitlementTenantId
  ) ?? null;
  const effectiveEntitlements = getNestedItem(selectedEntitlementTenant, ['effective_entitlements']);

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
        if (!canDecideSignups || !['submitted', 'under_review'].includes(state)) return '—';
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
        if (!canDecideApprovals || !['submitted', 'under_review'].includes(state)) return '—';
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
        Review queue <span className="tabular-nums">{queueDepth === null ? '—' : formatNumber(queueDepth)}</span> ·{' '}
        <span className="tabular-nums">{tenantCount === null ? '—' : formatNumber(tenantCount)}</span> tenants ·{' '}
        <span className="tabular-nums">{highScaleReviews === null ? '—' : formatNumber(highScaleReviews)}</span> SOC reviews pending
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
          <CalloutNote icon={ShieldCheck} tone="warn">Staff-only scope. Every approval, rejection, support-owner change, and entitlement mutation is authorization-checked and audit-backed.</CalloutNote>
          <Tabs value={activeAdminTab} options={adminTabOptions} onChange={setAdminTab} className="tabs-wrap" ariaLabel="Staff administration sections"
            getTabId={(id) => `staff-administration-sections-tab-${id}`}
            getPanelId={(id) => `staff-administration-sections-panel-${id}`} />
          {activeAdminTab === 'overview' ? (
            <div role="tabpanel" id="staff-administration-sections-panel-overview" aria-labelledby="staff-administration-sections-tab-overview" className="tab-panel"><>
              <div className="kpi-row" aria-label="Staff operations summary">
                <KpiCell label="Review queue" value={queueDepth === null ? '—' : formatNumber(queueDepth)} delta="Signup and approval work" />
                {canReadSignups ? <KpiCell label="Pending signups" value={pendingSignups === null ? '—' : formatNumber(pendingSignups)} delta="Staff decision required" /> : null}
                {canReadTenants ? <KpiCell label="Tenants" value={tenantCount === null ? '—' : formatNumber(tenantCount)} delta="Managed accounts" /> : null}
                {canReadApprovals ? <KpiCell label="SOC reviews" value={highScaleReviews === null ? '—' : formatNumber(highScaleReviews)} delta="High-scale governance" /> : null}
              </div>
              {canReadInternalAudit ? (
              <Card density="compact">
                <PanelCardHeader title="Recent internal activity" description="Latest audit-backed staff actions across managed tenants." trailing={<Badge tone="muted">{data.loadErrors.internalAudit ? 'Unavailable' : `${data.internalAudit.length} records`}</Badge>} />
                <CardContent>
                  <DataTable columns={auditColumns} items={data.internalAudit.slice(0, 6)} loadError={data.loadErrors.internalAudit} onRetry={() => void onRefresh()} empty={renderFriendlyEmptyState({ icon: FileCheck2, title: 'No internal audit events.', body: 'Staff decisions and support actions appear here after they are recorded.' })} />
                </CardContent>
              </Card>
              ) : null}
            </></div>
          ) : null}
          {activeAdminTab === 'signup-queue' ? (
            <div role="tabpanel" id="staff-administration-sections-panel-signup-queue" aria-labelledby="staff-administration-sections-tab-signup-queue" className="tab-panel"><Card density="compact" className="staff-queue-priority">
              <CardHeader>
                <CardTitle>Signup queue</CardTitle>
                <CardDescription>Requests in the staff-only signup review queue.</CardDescription>
              </CardHeader>
              <CardContent>
                <DataTable columns={signupColumns} items={data.internalSignupRequests} empty={renderFriendlyEmptyState({ icon: ClipboardList, title: 'No signup requests.', body: 'Reviewed account intake records will appear here after customers submit requests.' })} loadError={data.loadErrors.internalSignupRequests} onRetry={() => void onRefresh()} />
              </CardContent>
            </Card></div>
          ) : null}
          {activeAdminTab === 'tenants' ? (<div role="tabpanel" id="staff-administration-sections-panel-tenants" aria-labelledby="staff-administration-sections-tab-tenants" className="tab-panel">
            <Card density="compact">
              <CardHeader>
                <CardTitle>Tenant directory</CardTitle>
                <CardDescription>Managed tenant account and subscription metadata.</CardDescription>
              </CardHeader>
              <CardContent>
                <DataTable columns={tenantColumns} items={data.internalTenants} empty={renderFriendlyEmptyState({ icon: Target, title: 'No managed tenants.', body: 'Provisioned tenants appear here after staff approval creates account records.' })} loadError={data.loadErrors.internalTenants} onRetry={() => void onRefresh()} />
              </CardContent>
            </Card>
          {canWriteTenants ? (
          <Card>
            <CardHeader>
              <CardTitle>Support owner assignment</CardTitle>
              <CardDescription>Assign the AstraNull support owner for the selected tenant.</CardDescription>
            </CardHeader>
            <CardContent>
              <form className="product-form" onSubmit={async (event) => {
                event.preventDefault();
                const owner = String(new FormData(event.currentTarget).get('support_owner') ?? '').trim();
                if (!entitlementTenantId || !owner) {
                  setError('Select a tenant before assigning a support owner.');
                  return;
                }
                if (!await confirm({
                  title: 'Assign support owner',
                  description: `Assign support owner "${owner}" for tenant ${entitlementTenantId}?`,
                  confirmLabel: 'Assign owner',
                  confirmTone: 'default'
                })) return;
                await runStaffAction(`support-owner-${entitlementTenantId}`, () => requestJson(config, session, `/internal/admin/tenants/${encodeURIComponent(entitlementTenantId)}`, {
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
          ) : null}
          {canWriteEntitlements ? (
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
              ) : <p className="muted">Effective entitlement detail is available from the selected tenant detail record. You can still apply an explicit grant or revocation below.</p>}
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
          ) : null}
            </div>
          ) : null}
          {activeAdminTab === 'approvals' ? (
            <div role="tabpanel" id="staff-administration-sections-panel-approvals" aria-labelledby="staff-administration-sections-tab-approvals" className="tab-panel"><Card density="compact">
              <CardHeader>
                <CardTitle>Approval requests</CardTitle>
                <CardDescription>Unified internal approvals, including subscription exceptions.</CardDescription>
              </CardHeader>
              <CardContent>
                <DataTable columns={approvalColumns} items={data.internalApprovalRequests} empty={renderFriendlyEmptyState({ icon: ShieldCheck, title: 'No internal approvals.', body: 'Pending approval records will appear here when backend workflows create them.' })} loadError={data.loadErrors.internalApprovalRequests} onRetry={onRefresh ? () => void onRefresh() : undefined} />
              </CardContent>
            </Card></div>
          ) : null}
          {activeAdminTab === 'audit' ? (
            <div role="tabpanel" id="staff-administration-sections-panel-audit" aria-labelledby="staff-administration-sections-tab-audit" className="tab-panel"><Card density="compact">
              <CardHeader>
                <CardTitle>Internal audit</CardTitle>
                <CardDescription>Recent actions in the internal audit record.</CardDescription>
              </CardHeader>
              <CardContent>
                <DataTable columns={auditColumns} items={data.internalAudit} empty={renderFriendlyEmptyState({ icon: FileCheck2, title: 'No internal audit events.', body: 'Staff decisions and support actions will be listed after they are recorded.' })} loadError={data.loadErrors.internalAudit} onRetry={onRefresh ? () => void onRefresh() : undefined} />
              </CardContent>
            </Card></div>
          ) : null}

        </>
      )}
    </div>
  );
}
