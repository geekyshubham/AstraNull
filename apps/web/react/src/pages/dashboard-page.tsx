import { useEffect, useMemo, useState, type KeyboardEvent as ReactKeyboardEvent, type ReactNode } from 'react';
import { requestJson } from '../lib/api';
import { familyCoverageBuckets, inventoryUnits } from '../lib/domain-checks.mjs';
import { useOpenInspector } from '../components/evidence/use-inspector';
import {
  Activity,
  ChevronRight,
  Eye,
  ListChecks,
  Network,
  RefreshCw,
  Target,
  TriangleAlert
} from 'lucide-react';
import { ReadinessPostureDonut } from '../components/charts/readiness-posture-donut';
import { ScoreTrend } from '../components/charts/score-trend';
import { VectorHeatmap } from '../components/charts/vector-heatmap';
import { ResourceMatrix } from '../components/charts/resource-matrix';
import { Badge } from '../components/ui/badge';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '../components/ui/card';
import { EmptyState } from '../components/ui/empty-state';
import { AnchorButton, Button } from '../components/ui/button';
import { Tabs } from '../components/ui/tabs';
import { DataTable, type TableColumn } from '../components/ui/table';
import { VerifyChip } from '../lib/verify-chip';
import { useFindingTotals, useFindingsPage, useOpenFindingOverview } from '../components/findings/use-server-findings';
import { FINDINGS_LIMIT_MAX, findingsComplete } from '../lib/findings-query.mjs';
import {
  buildTargetPostureRows,
  classifyVerdict,
  resolveRecentRuns,
  severityDistributionFromCounts,
  severityShortLabel,
  type EvidenceStatus,
  type TargetPostureRow
} from '../lib/dashboard-metrics';
import { isFindingOpen } from '../lib/findings-helpers';
// @ts-ignore Plain ESM keeps run-start role parity testable with node:test.
import { canStartRun } from '../lib/run-permissions.mjs';
import { buildDetailHref } from '../lib/route-params';
import { routeTabs } from '../lib/prototype-manifest';
import type { BadgeTone, DataItem, PortalConfig, PortalData, ReadinessFactor, Session } from '../lib/types';
import { formatDate, formatNumber, formatSeverityLabel, pluralize, scoreTone } from '../lib/utils';
// @ts-ignore Plain ESM keeps executive terminology directly testable with node:test.
import { dashboardReadinessMessage, plainFindingTitle, plainInlineText, plainVerdictLabel } from '../lib/plain-language.mjs';
import { PageContextSummary, PageHeader } from './page-components';
import './dashboard-page.css';

type UiBadgeTone = BadgeTone;
type DashboardTabId = 'overview' | 'risk-trends';
const DASHBOARD_TAB_IDS: readonly DashboardTabId[] = ['overview', 'risk-trends'];
const DASHBOARD_TAB_STORAGE_KEY = 'astranull-dashboard-tab';
/** Placeholder for a value whose source failed to load. Plain text, no dash glyphs. */
const UNAVAILABLE = 'n/a';

function getString(item: DataItem | null | undefined, keys: string[], fallback = '') {
  if (!item) return fallback;
  for (const key of keys) {
    const value = item[key];
    if (value !== undefined && value !== null && value !== '') return String(value);
  }
  return fallback;
}

function getHashQueryParam(key: string) {
  if (typeof window === 'undefined') return '';
  const hash = window.location.hash.replace(/^#/, '');
  const query = hash.includes('?') ? hash.slice(hash.indexOf('?') + 1) : '';
  return new URLSearchParams(query || window.location.search).get(key) ?? '';
}

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

const STATUS_TONE: Record<EvidenceStatus, UiBadgeTone> = {
  pass: 'success',
  review: 'warn',
  gap: 'danger',
  none: 'muted'
};

function formatShortRelative(iso: string) {
  const ts = Date.parse(iso);
  if (!Number.isFinite(ts)) return UNAVAILABLE;
  const seconds = Math.round(Math.max(0, Date.now() - ts) / 1000);
  if (seconds < 60) return `${seconds}s ago`;
  const minutes = Math.round(seconds / 60);
  if (minutes < 120) return `${minutes}m ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 48) return `${hours}h ago`;
  return `${Math.round(hours / 24)}d ago`;
}

/* ---------- Prioritized fixes (evidence-backed, no agent step) ---------- */

const EMPTY_ROWS: DataItem[] = [];

const FINDING_PRIORITY: Record<string, number> = {
  s1: 0, critical: 0, s2: 1, high: 1, s3: 2, medium: 2, s4: 3, low: 3
};

type NextStep = { key: string; title: string; detail: string; href: string; tone: UiBadgeTone; findingId?: string; targetId?: string; checkId?: string };

function fixTitle(finding: DataItem, targets: DataItem[], checks: DataItem[]) {
  const context = [
    getString(finding, ['title', 'summary']),
    getString(finding, ['check_id']),
    getString(finding, ['vector_family', 'category'])
  ].join(' ').toLowerCase();
  const targetId = getString(finding, ['target_id']);
  const target = targets.find((item) => getString(item, ['id', 'target_id']) === targetId);
  const targetName = getString(target ?? {}, ['value', 'hostname'], getString(finding, ['target_hostname', 'target_value'], 'this target'));
  if (context.includes('origin') && (context.includes('bypass') || context.includes('direct') || context.includes('penetrated'))) {
    return `Block direct access to ${targetName}`;
  }
  if (context.includes('waf') || context.includes('web firewall')) return `Review web firewall blocking for ${targetName}`;
  if (context.includes('dns')) return `Review DNS protection for ${targetName}`;
  if (context.includes('authorization') || context.includes('approval')) return `Complete authorization for ${targetName}`;
  return `Review ${plainFindingTitle(finding, targets, checks)}`;
}

/** `priority` is the server's most severe open findings; `findingsUnavailable` when their read failed. */
function buildNextSteps(data: PortalData, priority: DataItem[], findingsUnavailable: boolean): NextStep[] {
  const steps: NextStep[] = [];
  const activeGroups = data.targetGroups.filter((group) => group.archived_at == null);
  const hasEvidence = data.runs.some((run) => {
    const status = getString(run, ['status']).toLowerCase();
    const verdict = typeof run.verdict === 'string' ? run.verdict : getString(run.verdict as DataItem, ['verdict', 'status']);
    return ['completed', 'verdicted', 'finalized'].includes(status) && classifyVerdict(verdict) !== 'none';
  });
  const openFindings = priority
    .filter(isFindingOpen)
    .sort((left, right) => (FINDING_PRIORITY[getString(left, ['severity']).toLowerCase()] ?? 9) - (FINDING_PRIORITY[getString(right, ['severity']).toLowerCase()] ?? 9));

  if (!findingsUnavailable) {
    for (const finding of openFindings.slice(0, 3)) {
      const id = getString(finding, ['id']);
      const severity = getString(finding, ['severity'], 'unknown');
      const title = fixTitle(finding, data.targets, data.checks);
      const plainTitle = plainFindingTitle(finding, data.targets, data.checks);
      const severityText = `${severityShortLabel(severity)} severity`;
      steps.push({
        key: `finding-${id || steps.length}`,
        title,
        // The fallback title already repeats the finding name; only add it when it adds information.
        detail: title === `Review ${plainTitle}` ? `${severityText} open finding` : `${severityText}: ${plainTitle}`,
        href: id ? buildDetailHref('finding-detail', id) : '#findings?status=open',
        tone: ['s1', 'critical', 's2', 'high'].includes(severity.toLowerCase()) ? 'danger' : 'warn',
        findingId: id || undefined,
        targetId: getString(finding, ['target_id']) || undefined,
        checkId: getString(finding, ['check_id']) || undefined
      });
    }
  }
  if (steps.length < 3 && !data.loadErrors.targets && data.targets.length === 0) {
    steps.push({
      key: 'declare-target',
      title: 'Declare the first target to protect',
      detail: 'Add a domain, hostname, IP, or CIDR before any check can run.',
      href: '#targets',
      tone: 'info'
    });
  }
  if (steps.length < 3 && !data.loadErrors.targets && data.targets.length > 0 && data.targets.every((target) => !isTargetVerified(target))) {
    steps.push({
      key: 'verify-ownership',
      title: 'Prove ownership on a declared target',
      detail: 'Ownership must reach DNS-verified before AstraNull sends live probes.',
      href: '#targets?verification=unverified',
      tone: 'info'
    });
  }
  if (steps.length < 3 && !data.loadErrors.runs && !hasEvidence && activeGroups.length > 0) {
    steps.push({
      key: 'first-run',
      title: 'Run the first bounded check on a target',
      detail: 'Open a verified target, review a compatible check and start it to create evidence.',
      href: '#targets?verification=verified',
      tone: 'info'
    });
  }
  return steps.slice(0, 3);
}

function isTargetVerified(target: DataItem) {
  const nested = target.verification;
  const state = nested && typeof nested === 'object' && !Array.isArray(nested)
    ? getString(nested as DataItem, ['state'])
    : getString(target, ['verification_state']);
  return ['dns_verified', 'provider_verified', 'user_confirmed', 'verified'].includes(state.toLowerCase());
}

/* ---------- Weighted readiness factors (compact) ---------- */

const READINESS_SCALE = 100;

function WeightedFactors({ factors }: { factors: ReadinessFactor[] }) {
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
    <div className="an-factor-list" data-testid="readiness-factors">
      {rows.map((factor, index) => {
        const key = getString(factor as DataItem, ['key']);
        const label = plainInlineText(getString(factor as DataItem, ['label', 'key'], 'Factor'));
        const score = Number(factor.score);
        const scale = typeof factor.weight === 'number' && Number.isFinite(factor.weight) && factor.weight > 0 ? factor.weight : READINESS_SCALE;
        const share = Math.min(100, Math.max(0, (score / scale) * 100));
        const detail = plainInlineText(getString(factor as DataItem, ['detail', 'reason']));
        const provenance = `${label}: ${score} of ${scale} points, from GET /v1/state readiness.factors`;
        return (
          <div className="factor-row" key={key || `${label}-${index}`} data-testid="readiness-factor-row">
            <span className="factor-name" title={provenance}>{label}</span>
            <span className="factor-score">{score}/{scale}</span>
            <span className="factor-track" role="img" aria-label={`${label} scored ${score} of ${scale} points`}>
              <span className="factor-fill" data-tone={scoreTone(share)} style={{ width: `${share}%` }} />
            </span>
            {detail ? <p className="factor-detail">{detail}</p> : null}
          </div>
        );
      })}
    </div>
  );
}

/* ---------- KPI card: whole card is the hit area when it navigates ---------- */

function KpiCard({
  label,
  value,
  sub,
  href,
  onActivate,
  actionLabel
}: {
  label: string;
  value: ReactNode;
  sub: ReactNode;
  href?: string;
  onActivate?: () => void;
  actionLabel?: string;
}) {
  const body = (
    <>
      <span className="dashboard-kpi-top">
        <span className="dashboard-kpi-label">{label}</span>
        {href || onActivate ? <ChevronRight className="dashboard-kpi-chevron" size={16} aria-hidden="true" /> : null}
      </span>
      <span className="dashboard-kpi-value">{value}</span>
      {sub}
      {actionLabel ? <span className="sr-only">{actionLabel}</span> : null}
    </>
  );
  if (href) {
    return <a className="dashboard-kpi is-interactive" href={href}>{body}</a>;
  }
  if (onActivate) {
    return <button type="button" className="dashboard-kpi is-interactive" onClick={onActivate}>{body}</button>;
  }
  return <div className="dashboard-kpi">{body}</div>;
}

/* ---------- Declared-host coverage (server analytics only) ---------- */

type CoverageFamily = 'waf' | 'cdn';
type CoverageUnit = 'normalized_hostname' | 'declared_target';
type CoverageResult =
  | { state: 'loading' }
  | { state: 'ready'; payload: DataItem }
  | { state: 'unsupported' }
  | { state: 'denied' }
  | { state: 'error'; message: string };

function useDeclaredHostCoverage(config: PortalConfig, session: Session, family: CoverageFamily, unit: CoverageUnit, reload: number): CoverageResult {
  const [result, setResult] = useState<CoverageResult>({ state: 'loading' });
  useEffect(() => {
    const controller = new AbortController();
    setResult({ state: 'loading' });
    requestJson(config, session, `/v1/analytics/declared-hosts?family=${family}&unit=${unit}&limit=1`, { signal: controller.signal })
      .then((payload) => { if (!controller.signal.aborted) setResult({ state: 'ready', payload: payload as DataItem }); })
      .catch((err) => {
        if (controller.signal.aborted) return;
        const status = (err as { status?: number }).status;
        if (status === 404) setResult({ state: 'unsupported' });
        else if (status === 403) setResult({ state: 'denied' });
        else setResult({ state: 'error', message: err instanceof Error ? err.message : 'Coverage could not load.' });
      });
    return () => controller.abort();
  }, [config, session, family, unit, reload]);
  return result;
}

function CoverageRow({ family, result, onRetry }: { family: CoverageFamily; result: CoverageResult; onRetry: () => void }) {
  const title = family === 'waf' ? 'WAF observations' : 'CDN observations';
  if (result.state === 'loading') return <div className="coverage-row" aria-busy="true"><span className="coverage-title">{title}</span><div className="skeleton skeleton-row" /></div>;
  if (result.state !== 'ready') {
    return (
      <div className="coverage-row">
        <span className="coverage-title">{title}</span>
        <span className="coverage-unavailable">
          {result.state === 'unsupported' ? 'Unavailable: this server does not report declared-host coverage.' : result.state === 'denied' ? 'Access required to read target analytics.' : <>Unavailable: {result.message} <Button size="sm" variant="ghost" onClick={onRetry}>Retry</Button></>}
        </span>
      </div>
    );
  }
  const buckets = familyCoverageBuckets(result.payload);
  const unitNoun = buckets.unit === 'target' ? 'declared target records' : 'distinct hostnames';
  if (!buckets.complete) {
    return (
      <div className="coverage-row">
        <span className="coverage-title">{title}</span>
        <span className="coverage-unavailable">Unavailable: the server could not read the complete scope, so no partial count is shown.</span>
      </div>
    );
  }
  if (!buckets.denominator) {
    return (
      <div className="coverage-row">
        <span className="coverage-title">{title}</span>
        <span className="coverage-unavailable">Not applicable: no {unitNoun} in the current declared scope.</span>
      </div>
    );
  }
  const shown = buckets.parts.filter((part) => part.group !== 'unmeasured');
  const unmeasuredParts = buckets.parts.filter((part) => part.group === 'unmeasured');
  const barParts = [...shown, { key: 'unmeasured', label: 'Unknown or not checked', group: 'unmeasured', count: buckets.unmeasured, href: '' }];
  return (
    <div className="coverage-row">
      <span className="coverage-title">{title}</span>
      <span className="coverage-bar" role="img" aria-label={`${title}: ${barParts.map((part) => `${part.label} ${part.count}`).join(', ')}, of ${buckets.denominator} ${unitNoun}`}>
        {barParts.filter((part) => part.count > 0).map((part) => <span key={part.key} className="coverage-seg" data-segment={part.group} style={{ flexGrow: part.count }} />)}
      </span>
      <ul className="coverage-legend">
        {shown.map((part) => (
          <li key={part.key}>
            <a href={part.href} aria-label={`${title} ${part.label.toLowerCase()}: ${formatNumber(part.count)} ${unitNoun}. Open the matching list.`}>
              <span className="coverage-swatch" data-segment={part.group} aria-hidden="true" />
              {part.label} <span className="tabular-nums">{formatNumber(part.count)}</span>
            </a>
          </li>
        ))}
        <li className="coverage-legend-group">
          <span className="coverage-swatch" data-segment="unmeasured" aria-hidden="true" />
          <span>Unknown or not checked <span className="tabular-nums">{formatNumber(buckets.unmeasured)}</span>:</span>
          {unmeasuredParts.map((part, index) => (
            <span key={part.key}>
              {index ? ' · ' : ' '}
              <a href={part.href} aria-label={`${title} ${part.label.toLowerCase()}: ${formatNumber(part.count)} ${unitNoun}. Open the matching list.`}>{part.label} <span className="tabular-nums">{formatNumber(part.count)}</span></a>
            </span>
          ))}
        </li>
      </ul>
      <span className="coverage-meta">
        of <span className="tabular-nums">{formatNumber(buckets.denominator)}</span> {unitNoun}
        {' '}(same scope: {buckets.units.targetRecords === null ? 'not reported' : formatNumber(buckets.units.targetRecords)} declared target records, {buckets.units.normalizedHosts === null ? 'not reported' : formatNumber(buckets.units.normalizedHosts)} distinct hostnames)
        {buckets.asOf ? ` · current as of ${formatDate(buckets.asOf)}` : ''}
        {buckets.current ? '' : ' · scope not confirmed as current'}
        {buckets.reconciled ? '' : ' · reported segments do not add up to the total; counts are shown as reported'}
      </span>
    </div>
  );
}

// Server verification states that count as ownership verified (lib/dashboard-metrics VERIFIED_STATES).
const VERIFIED_SERVER_STATES = ['dns_verified', 'provider_verified', 'user_confirmed'] as const;

/** Exact verified-target total from the server, one `limit=1` filtered read per verified state. */
function useVerifiedTargetTotal(config: PortalConfig, session: Session, enabled: boolean, reload: number): number | null {
  const [total, setTotal] = useState<number | null>(null);
  useEffect(() => {
    if (!enabled) return undefined;
    const controller = new AbortController();
    setTotal(null);
    Promise.all(VERIFIED_SERVER_STATES.map((state) => requestJson(config, session, `/v1/targets?verification_state=${state}&unit=target&limit=1`, { signal: controller.signal })
      .then((body) => {
        const value = (body as DataItem | null)?.total;
        return typeof value === 'number' && Number.isFinite(value) ? value : null;
      })))
      .then((values) => {
        if (!controller.signal.aborted) setTotal(values.every((value) => value !== null) ? values.reduce<number>((sum, value) => sum + (value ?? 0), 0) : null);
      })
      .catch(() => {
        if (!controller.signal.aborted) setTotal(null);
      });
    return () => controller.abort();
  }, [config, session, enabled, reload]);
  return enabled ? total : null;
}

function finiteCount(value: unknown) {
  return typeof value === 'number' && Number.isFinite(value) && value >= 0 ? value : null;
}

function DeclaredHostCoverage({ waf, cdn, unit, onUnit, onRetry }: { waf: CoverageResult; cdn: CoverageResult; unit: CoverageUnit; onUnit: (unit: CoverageUnit) => void; onRetry: () => void }) {
  return (
    <section className="declared-coverage" aria-labelledby="declared-coverage-title">
      <div className="declared-coverage-head">
        <div>
          <h2 id="declared-coverage-title">Declared host protection observations</h2>
          <p>WAF and CDN fingerprints across your current declared scope, counted by the server. Detection is not effectiveness, and unknown stays unknown. Each count opens the exact matching list.</p>
        </div>
        <div className="coverage-unit" role="group" aria-label="Count by">
          <button type="button" aria-pressed={unit === 'normalized_hostname'} onClick={() => onUnit('normalized_hostname')}>Distinct hostnames</button>
          <button type="button" aria-pressed={unit === 'declared_target'} onClick={() => onUnit('declared_target')}>Declared target records</button>
        </div>
      </div>
      <CoverageRow family="waf" result={waf} onRetry={onRetry} />
      <CoverageRow family="cdn" result={cdn} onRetry={onRetry} />
    </section>
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
  const [refreshing, setRefreshing] = useState(false);
  const tabOptions = routeTabs('dashboard').map((item) => ({ id: item.id as DashboardTabId, label: item.label }));

  useEffect(() => {
    const onHashChange = () => {
      const next = readDashboardTabId();
      setTab((current) => (current === next ? current : next));
    };
    window.addEventListener('hashchange', onHashChange);
    return () => window.removeEventListener('hashchange', onHashChange);
  }, []);

  function handleTabChange(next: DashboardTabId) {
    setTab(next);
    persistDashboardTab(next);
  }

  async function handleRefresh() {
    setRefreshing(true);
    setFindingsReload((value) => value + 1);
    try {
      await onRefresh();
    } finally {
      setRefreshing(false);
    }
  }

  const score = typeof data.state?.readiness?.score === 'number' ? data.state.readiness.score : null;
  const readinessFactors = Array.isArray(data.state?.readiness?.factors) ? data.state!.readiness!.factors! : [];
  const openInspector = useOpenInspector();
  // Finding counts on this page are server predicates, never the shell's first loaded page.
  const [findingsReload, setFindingsReload] = useState(0);
  const [coverageUnit, setCoverageUnit] = useState<CoverageUnit>('normalized_hostname');
  const [coverageReload, setCoverageReload] = useState(0);
  const wafCoverage = useDeclaredHostCoverage(config, session, 'waf', coverageUnit, coverageReload);
  const cdnCoverage = useDeclaredHostCoverage(config, session, 'cdn', coverageUnit, coverageReload);
  const openSample = useFindingsPage(config, session, { status: 'open', limit: FINDINGS_LIMIT_MAX }, findingsReload);
  const openOverview = useOpenFindingOverview(config, session, findingsReload, 3, 8, openSample);
  const sampleRows = openSample.envelope?.items ?? EMPTY_ROWS;
  const sampleComplete = findingsComplete(openSample.envelope, sampleRows.length);
  const provisionalRows = buildTargetPostureRows(data, 6, { openFindings: sampleRows });
  // More open findings than one page: the visible rows get exact per-target server counts.
  const rowTotals = useFindingTotals(
    config,
    session,
    Object.fromEntries(provisionalRows.map((row) => [row.id, { status: 'open', target_id: row.id }])),
    findingsReload,
    openSample.state === 'ready' && !sampleComplete && provisionalRows.length > 0
  );
  const openCounts = useMemo(() => {
    if (sampleComplete || rowTotals.state !== 'ready') return undefined;
    return new Map(Object.entries(rowTotals.totals).flatMap(([id, value]) => (typeof value === 'number' ? [[id, value] as [string, number]] : [])));
  }, [sampleComplete, rowTotals]);
  const countsLoading = openOverview.total === null && openOverview.state === 'loading';
  const countsUnavailable = openOverview.total === null && openOverview.state === 'error';
  const units = inventoryUnits(data.targets);
  const recentRuns = resolveRecentRuns(data, 6);
  const postureRows = buildTargetPostureRows(data, 6, { openFindings: sampleRows, openCounts });
  const nextSteps = buildNextSteps(data, openOverview.priority, countsUnavailable || (openOverview.state === 'error' && openOverview.priority.length === 0));
  const severity = openOverview.severity && openOverview.total !== null
    ? { critical: openOverview.severity.critical, high: openOverview.severity.high, other: openOverview.severity.medium + openOverview.severity.low + openOverview.severity.unrecorded, total: openOverview.total }
    : { critical: 0, high: 0, other: 0, total: 0 };

  const targetsUnavailable = Boolean(data.loadErrors.targets);
  // Declared scope comes from the server's own count (the same units as the observation cohorts).
  // Loaded rows stand in only when the server count is unavailable, or when they are that whole set.
  const serverUnits = wafCoverage.state === 'ready' && wafCoverage.payload.units && typeof wafCoverage.payload.units === 'object' ? wafCoverage.payload.units as DataItem : null;
  const serverRecords = finiteCount(serverUnits?.target_records);
  const serverHosts = finiteCount(serverUnits?.normalized_hosts);
  const loadedIsWholeScope = serverRecords === null || data.targets.length === serverRecords;
  const serverVerified = useVerifiedTargetTotal(config, session, !targetsUnavailable && !loadedIsWholeScope, coverageReload);
  const declaredTargets = serverRecords ?? data.targets.length;
  const distinctHosts = serverHosts ?? units.distinctHosts;
  const verifiedTargets: number | null = loadedIsWholeScope ? data.targets.filter(isTargetVerified).length : serverVerified;
  const verifiedShare = declaredTargets > 0 && verifiedTargets !== null ? Math.round((verifiedTargets / declaredTargets) * 100) : null;

  // Evidence coverage: declared targets with at least one evidence-backed verdict.
  const allPostureRows = buildTargetPostureRows(data, undefined, { openFindings: sampleRows, openCounts });
  const targetsWithEvidence = new Set(
    allPostureRows.filter((row) => row.verdictStatus !== 'none').map((row) => row.id)
  ).size;
  // Posture tally across every declared target, worst first, for the scannable summary line.
  const postureTally = (['gap', 'review', 'pass', 'none'] as EvidenceStatus[]).map((status) => ({
    status,
    count: allPostureRows.filter((row) => row.verdictStatus === status).length
  }));
  const coverageUnavailable = targetsUnavailable || Boolean(data.loadErrors.runs);
  const coveragePercent = coverageUnavailable || declaredTargets === 0 ? null : Math.round((targetsWithEvidence / declaredTargets) * 100);

  const lastValidationIso = getString(data.state ?? {}, ['last_validation_at'])
    || (recentRuns[0] ? String(recentRuns[0].completed_at ?? recentRuns[0].started_at ?? recentRuns[0].created_at ?? '') : '');
  const lastValidationLabel = data.loadErrors.runs ? UNAVAILABLE : lastValidationIso ? formatShortRelative(lastValidationIso) : 'Never';

  const executive = dashboardReadinessMessage({
    score,
    highPriorityFindings: severity.critical + severity.high,
    coveragePercent,
    dataUnavailable: Boolean(data.error || data.loadErrors.targets || data.loadErrors.runs || data.loadErrors.evidence || countsUnavailable)
  });

  const tenantId = getString(data.tenant ?? {}, ['id', 'tenant_id']) || getString((data.state ?? {}) as DataItem, ['tenant_id']);
  const tenantEyebrow = tenantId ? `Tenant · ${tenantId.toUpperCase()}` : 'Tenant';

  const killSwitch = data.state?.kill_switch ?? null;
  const killSwitchArmed = killSwitch?.active === true;
  const killSwitchReason = getString((killSwitch ?? {}) as DataItem, ['reason']);
  const killSwitchUpdatedAt = getString((killSwitch ?? {}) as DataItem, ['updated_at']);

  const postureColumns: TableColumn<TargetPostureRow>[] = [
    {
      key: 'target',
      label: 'Target',
      render: (row) => (
        <span className="posture-target">
          <strong title={row.value}>{row.value}</strong>
          <span className="posture-tags">
            {row.tags.length > 0
              ? row.tags.slice(0, 4).map((tag) => <span className="posture-tag" key={tag}>{tag}</span>)
              : <span className="posture-tags-empty">No tags</span>}
            {row.tags.length > 4 ? <span className="posture-tag">+{row.tags.length - 4}</span> : null}
          </span>
        </span>
      )
    },
    {
      key: 'verification',
      label: 'Ownership',
      render: (row) => <VerifyChip state={row.verificationState} label={ownershipShortLabel(row.verificationState)} />
    },
    {
      key: 'verdict',
      label: 'Recorded verdict',
      render: (row) => (
        <span className="posture-verdict">
          <Badge
            tone={STATUS_TONE[row.verdictStatus]}
            title={row.verdict
              ? `${plainVerdictLabel(row.verdict)}${row.verdictRunId ? ` (run ${row.verdictRunId})` : ''}`
              : row.verdictBasis === 'unbacked' ? 'A run finished without a recorded verdict or evidence, so it is not counted.' : 'No evidence-backed verdict yet'}
          >
            {row.verdict
              ? row.openFindings > 0 && classifyVerdict(row.verdict) === 'pass'
                ? `Passed · ${row.openFindings} open`
                : postureVerdictLabel(row.verdictStatus)
              : row.verdictBasis === 'unbacked' ? 'Not recorded' : 'No result'}
          </Badge>
          {row.verdictBasis === 'earlier' ? <span className="posture-verdict-note">Earlier run; newest has no recorded verdict</span> : null}
        </span>
      )
    }
  ];

  const runColumns: TableColumn<DataItem>[] = [
    {
      key: 'run',
      label: 'Run',
      render: (item) => (
        <span className="posture-target">
          <strong>{getString(item, ['target_hostname', 'target_value'], getString(item, ['check_id'], 'Validation run'))}</strong>
          <small className="mono">{getString(item, ['id'], UNAVAILABLE)}</small>
        </span>
      )
    },
    {
      key: 'verdict',
      label: 'Verdict',
      render: (item) => {
        const raw = typeof item.verdict === 'string' ? item.verdict : getString(item.verdict as DataItem, ['verdict', 'status', 'result']);
        const status = classifyVerdict(raw);
        return <Badge tone={STATUS_TONE[status]} title={raw || 'No verdict'}>{raw ? plainVerdictLabel(raw) : 'No result yet'}</Badge>;
      }
    },
    {
      key: 'when',
      label: 'When',
      render: (item) => <span className="muted nowrap">{formatShortRelative(String(item.completed_at ?? item.started_at ?? item.created_at ?? ''))}</span>
    }
  ];

  function rowProps(route: string, id: string, label: string) {
    if (!id) return {};
    const href = buildDetailHref(route, id);
    const navigate = () => {
      const hashIndex = href.indexOf('#');
      window.location.hash = hashIndex >= 0 ? href.slice(hashIndex + 1) : href;
    };
    return {
      tabIndex: 0,
      style: { cursor: 'pointer' as const },
      'aria-label': label,
      onClick: () => { navigate(); },
      onKeyDown: (event: ReactKeyboardEvent) => {
        if (event.key !== 'Enter' && event.key !== ' ') return;
        event.preventDefault();
        navigate();
      }
    };
  }

  function runInspectProps(item: DataItem) {
    const runId = getString(item, ['id']);
    const targetId = getString(item, ['target_id']);
    const checkId = getString(item, ['check_id']);
    if (!runId || !targetId || !checkId) return {};
    const open = () => openInspector({ entry: 'check_result', target_id: targetId, check_id: checkId, test_run_id: runId }, `dash-run-${runId}`);
    return {
      tabIndex: 0,
      role: 'button',
      'data-focus-key': `dash-run-${runId}`,
      style: { cursor: 'pointer' as const },
      'aria-label': `View evidence for ${getString(item, ['target_hostname', 'target_value'], checkId)} check ${checkId}`,
      onClick: open,
      onKeyDown: (event: ReactKeyboardEvent) => {
        if (event.key !== 'Enter' && event.key !== ' ') return;
        event.preventDefault();
        open();
      }
    };
  }

  // Oldest first by recorded open date; findings without a date sort last, never as "oldest".
  // Oldest open findings: the server's last pages of status=open, oldest first.
  const agingFindings = openOverview.oldest.filter(isFindingOpen);

  // Severity split for the risk-trends findings panel from exact server counts per severity.
  const severityDist = severityDistributionFromCounts(openOverview.severity ?? { critical: 0, high: 0, medium: 0, low: 0, unrecorded: 0 });
  const severitySlices = severityDist.slices.filter((slice) => slice.key !== 'unrecorded' || slice.count > 0);
  const severityStackLabel = `${formatNumber(severityDist.total)} open ${pluralize(severityDist.total, 'finding')}: ${severitySlices
    .map((slice) => `${slice.label} ${formatNumber(slice.count)}`)
    .join(', ')}`;

  return (
    <div className="content dashboard-page">
      <PageHeader
        route="dashboard"
        eyebrow={tenantEyebrow}
        title="Readiness overview"
        description="Every verdict below traces to observed probe evidence or an explicit customer declaration. Validation runs from the outside in."
        actions={
          <>
            <Button type="button" variant="secondary" size="sm" loading={refreshing} onClick={() => void handleRefresh()}>
              <RefreshCw size={15} aria-hidden="true" /> Refresh
            </Button>
            {canStartRun(session.role) ? (
              <AnchorButton href="#targets" variant="default" size="sm">Validate a target</AnchorButton>
            ) : null}
          </>
        }
      />
      <PageContextSummary>
        <span className="tabular-nums">{targetsUnavailable ? UNAVAILABLE : formatNumber(declaredTargets)}</span>{' '}
        {`declared ${pluralize(declaredTargets, 'target')}, `}
        <span className="tabular-nums">{targetsUnavailable ? UNAVAILABLE : verifiedTargets === null ? '...' : formatNumber(verifiedTargets)}</span>{' '}
        {`ownership verified, `}
        <span className="tabular-nums">{data.loadErrors.evidence ? UNAVAILABLE : formatNumber(data.evidence.length)}</span>{' '}
        {`evidence ${pluralize(data.evidence.length, 'record')}. All checks run bounded from the outside in.`}
      </PageContextSummary>
      <Tabs
        value={tab}
        options={tabOptions}
        onChange={handleTabChange}
        className="tabs-wrap"
        ariaLabel="Dashboard sections"
        getTabId={(id) => `dashboard-sections-tab-${id}`}
        getPanelId={(id) => `dashboard-sections-panel-${id}`}
      />

      {killSwitchArmed ? (
        <div className="form-banner error stack-tight" role="alert">
          <strong>SOC kill switch is armed</strong>
          {killSwitchReason ? <span title="Kill switch reason from GET /v1/state kill_switch.reason">{killSwitchReason}</span> : null}
          {killSwitchUpdatedAt ? <span title="Kill switch updated_at from GET /v1/state kill_switch.updated_at">Armed {formatDate(killSwitchUpdatedAt)}</span> : null}
        </div>
      ) : null}

      {tab === 'overview' ? (
        <div role="tabpanel" id="dashboard-sections-panel-overview" aria-labelledby="dashboard-sections-tab-overview" className="tab-panel dashboard-overview">
          <div className="dashboard-kpis" role="group" aria-label="Readiness key metrics">
            <KpiCard
              label="Readiness"
              value={<>{score ?? UNAVAILABLE}{score !== null ? <span className="unit">/100</span> : null}</>}
              sub={<><span className="dashboard-kpi-sub">{executive.headline}</span><span className="dashboard-kpi-sub dashboard-kpi-scope">Published score over target groups with evidence in the last 30 days. Not a protection guarantee.</span></>}
              onActivate={() => {
                handleTabChange('risk-trends');
                // The KPI unmounts with the overview panel; hand focus to the tab it opened.
                window.requestAnimationFrame(() => document.getElementById('dashboard-sections-tab-risk-trends')?.focus());
              }}
              actionLabel="Open readiness trend"
            />
            <KpiCard
              label="Declared targets"
              value={targetsUnavailable ? UNAVAILABLE : formatNumber(declaredTargets)}
              sub={<span className="dashboard-kpi-sub">{targetsUnavailable ? 'Target data unavailable' : declaredTargets === 0 ? 'No targets declared yet' : `${formatNumber(distinctHosts)} distinct hostnames · ${verifiedTargets === null ? 'ownership verified count loading' : `${formatNumber(verifiedTargets)} ownership verified (${verifiedShare}%)`}`}</span>}
              href="#targets"
              actionLabel="Open all declared targets"
            />
            <KpiCard
              label="Ownership pending"
              value={targetsUnavailable ? UNAVAILABLE : verifiedTargets === null ? '...' : formatNumber(declaredTargets - verifiedTargets)}
              sub={<span className="dashboard-kpi-sub">{targetsUnavailable ? 'Target data unavailable' : 'Locked targets: no external check can run until ownership is proven'}</span>}
              href="#targets?verification=unverified"
              actionLabel="Open targets with ownership pending"
            />
            <KpiCard
              label="Open findings"
              value={countsUnavailable ? UNAVAILABLE : countsLoading ? '...' : formatNumber(severity.total)}
              sub={countsUnavailable || countsLoading ? (
                <span className="dashboard-kpi-sub">{countsUnavailable ? 'Finding counts unavailable' : 'Counting open findings'}</span>
              ) : (
                <span className="dashboard-kpi-split">
                  <Badge tone="danger" title="Severity 1 (Critical)">{formatNumber(severity.critical)} critical</Badge>
                  <Badge tone="warn" title="Severity 2 (High)">{formatNumber(severity.high)} high</Badge>
                </span>
              )}
              href="#findings?status=open"
              actionLabel="Open the open findings queue"
            />
          </div>

          <div className="an-dash-grid">
            <div className="dash-area-coverage">
              <DeclaredHostCoverage waf={wafCoverage} cdn={cdnCoverage} unit={coverageUnit} onUnit={setCoverageUnit} onRetry={() => setCoverageReload((value) => value + 1)} />
            </div>
            <Card className="dash-area-readiness">
              <CardHeader>
                <div>
                  <CardTitle>Why this readiness score</CardTitle>
                  <CardDescription>Latest evidence-backed result per check across loaded runs, and the weighted factors behind the published score. A passing check covers its own scenario only{severity.critical + severity.high > 0 ? `; ${formatNumber(severity.critical + severity.high)} high-priority findings remain open` : ''}.</CardDescription>
                </div>
              </CardHeader>
              <CardContent>
                <div className="readiness-split">
                  <section className="readiness-split-pane" aria-labelledby="dash-posture-breakdown-title">
                    <h3 className="dash-subhead" id="dash-posture-breakdown-title">Check verdicts</h3>
                    <ReadinessPostureDonut state={data.state} runs={data.runs} checks={data.checks} />
                  </section>
                  <section className="readiness-split-pane" aria-labelledby="dash-weighted-factors-title">
                    <h3 className="dash-subhead" id="dash-weighted-factors-title">Weighted factors</h3>
                    <p className="dash-subhead-note">Each factor contributes its points to the published readiness score.</p>
                    <WeightedFactors factors={readinessFactors} />
                  </section>
                </div>
              </CardContent>
            </Card>

            <Card className="dash-area-targets">
              <CardHeader>
                <div>
                  <CardTitle>Target posture</CardTitle>
                  <CardDescription>Declared targets, worst posture first. Open a row for its evidence and checks.</CardDescription>
                </div>
                <AnchorButton variant="ghost" size="sm" href="#targets">All targets</AnchorButton>
              </CardHeader>
              <CardContent>
                {!targetsUnavailable && !data.loadErrors.runs && declaredTargets > 0 ? (
                  <ul className="posture-tally" aria-label={`Recorded verdict across ${formatNumber(declaredTargets)} declared ${pluralize(declaredTargets, 'target')}`}>
                    {postureTally.map(({ status, count }) => (
                      <li key={status} data-status={status} data-empty={count === 0 ? 'true' : undefined}>
                        <span className="posture-tally-value">{formatNumber(count)}</span>
                        <span className="posture-tally-label">{postureVerdictLabel(status)}</span>
                      </li>
                    ))}
                  </ul>
                ) : null}
                <DataTable
                  columns={postureColumns}
                  items={postureRows}
                  loadError={[data.loadErrors.targets, data.loadErrors.runs].filter(Boolean).join(' ') || null}
                  onRetry={() => void onRefresh()}
                  getRowId={(row) => row.id}
                  getRowProps={(row) => rowProps('target-detail', row.id, `Open target ${row.value} detail`)}
                  empty={<EmptyState icon={Target} title="No targets declared yet." body="Declare a domain, hostname, IP, or CIDR to start validating readiness." actionHref="#targets" actionLabel="Declare a target" />}
                />
                {!targetsUnavailable && !data.loadErrors.runs && declaredTargets > postureRows.length ? (
                  <p className="posture-more">
                    {`Showing the ${formatNumber(postureRows.length)} worst of ${formatNumber(declaredTargets)} declared targets. `}
                    <a href="#targets">See every target</a>
                  </p>
                ) : null}
                {openSample.state === 'ready' && !sampleComplete && openSample.envelope?.total ? (
                  <p className="posture-more">
                    {`The tally and row order use the newest ${formatNumber(sampleRows.length)} of ${formatNumber(openSample.envelope.total)} open findings, so a target tallied as passed may still have an older open finding. ${openCounts ? 'Open counts on these rows are exact server counts.' : 'Exact open counts for these rows are loading.'}`}
                  </p>
                ) : null}
              </CardContent>
            </Card>

            <Card className="dash-area-fixes">
              <CardHeader>
                <div>
                  <CardTitle>What to fix first</CardTitle>
                  <CardDescription>Highest-severity open findings first. View evidence shows the proof that opened each one.</CardDescription>
                </div>
                {nextSteps.length > 0 ? <Badge tone="warn">{`${formatNumber(nextSteps.length)} to review`}</Badge> : null}
              </CardHeader>
              <CardContent>
                {nextSteps.length > 0 ? (
                  <ol className="fix-list">
                    {nextSteps.map((step, index) => (
                      <li className="fix-row" key={step.key}>
                        <span className="fix-rank" data-tone={step.tone} aria-hidden="true">{index + 1}</span>
                        <span className="fix-copy">
                          <strong>{step.title}</strong>
                          <span>{step.detail}</span>
                        </span>
                        {step.findingId ? (
                          <span className="fix-actions">
                            <Button
                              variant="secondary"
                              size="sm"
                              data-focus-key={`dash-finding-${step.findingId}`}
                              onClick={() => openInspector({ entry: 'finding', finding_id: step.findingId!, target_id: step.targetId, check_id: step.checkId }, `dash-finding-${step.findingId}`)}
                              aria-label={`View evidence for ${step.title}`}
                            >
                              <Eye size={14} aria-hidden="true" />View evidence
                            </Button>
                            <AnchorButton href={step.href} variant="ghost" size="sm" aria-label={`Open finding for ${step.title}`}>Finding</AnchorButton>
                          </span>
                        ) : (
                          <AnchorButton href={step.href} variant="secondary" size="sm">Review</AnchorButton>
                        )}
                      </li>
                    ))}
                  </ol>
                ) : countsUnavailable || (openOverview.state === 'error' && severity.total > 0) ? (
                  <EmptyState icon={TriangleAlert} title="Priority fixes unavailable." body="Findings did not load, so AstraNull cannot rank what to fix first." actionLabel="Retry" onAction={() => setFindingsReload((value) => value + 1)} />
                ) : (
                  <EmptyState icon={ListChecks} title="No open finding needs a fix." body="Keep scheduled validation current so new evidence-backed gaps surface here first." />
                )}
              </CardContent>
            </Card>

            <Card className="dash-area-activity">
              <CardHeader>
                <div>
                  <CardTitle>Recent validation activity</CardTitle>
                  <CardDescription>Latest recorded checks. Select a row to view that result and its evidence.</CardDescription>
                </div>
              </CardHeader>
              <CardContent>
                <DataTable
                  columns={runColumns}
                  items={recentRuns}
                  loadError={data.loadErrors.runs}
                  onRetry={() => void onRefresh()}
                  getRowId={(item) => getString(item, ['id'])}
                  getRowProps={(item) => runInspectProps(item)}
                  empty={<EmptyState icon={ListChecks} title="No recorded checks yet." body="Open a verified target, review a compatible check and start it." actionHref="#targets" actionLabel="Open targets" />}
                />
              </CardContent>
            </Card>
          </div>
        </div>
      ) : null}

      {tab === 'risk-trends' ? (
        <div role="tabpanel" id="dashboard-sections-panel-risk-trends" aria-labelledby="dashboard-sections-tab-risk-trends" className="tab-panel">
          <div className="risk-trends">
            <Card className="risk-trends-hero">
              <CardHeader>
                <div>
                  <CardTitle>Readiness trend</CardTitle>
                  <CardDescription>Published per-run readiness scores, oldest to newest. Runs without a score show their evidence-backed verdict instead.</CardDescription>
                </div>
              </CardHeader>
              <CardContent>
                {data.loadErrors.runs ? (
                  <EmptyState icon={Activity} title="Run history unavailable." body="The readiness trend appears once validation runs load." actionLabel="Retry" onAction={() => void onRefresh()} />
                ) : (
                  <ScoreTrend runs={data.runs} currentScore={score} />
                )}
              </CardContent>
            </Card>

            <Card className="risk-secondary">
              <CardHeader>
                <div>
                  <CardTitle>Open findings</CardTitle>
                  <CardDescription>Severity split of every open finding, counted by the server, and the oldest gaps still waiting on a fix.</CardDescription>
                </div>
                <AnchorButton variant="ghost" size="sm" href="#findings">All findings</AnchorButton>
              </CardHeader>
              <CardContent>
                {countsUnavailable ? (
                  <EmptyState icon={TriangleAlert} title="Finding data unavailable." body="Severity and aging appear once findings load." actionLabel="Retry" onAction={() => setFindingsReload((value) => value + 1)} />
                ) : severityDist.total === 0 ? (
                  <EmptyState icon={TriangleAlert} title="No open findings." body="Open findings appear after validation runs produce evidence-backed gaps." actionLabel="Open findings" actionHref="#findings" />
                ) : (
                  <div className="risk-findings">
                    <section className="risk-findings-severity" aria-labelledby="risk-severity-title">
                      <div className="risk-findings-head">
                        <h3 className="dash-subhead" id="risk-severity-title">By severity</h3>
                        <span className="risk-findings-total">
                          <strong className="tabular-nums">{formatNumber(severityDist.total)}</strong> open
                        </span>
                      </div>
                      <div className="severity-stack" role="img" aria-label={severityStackLabel}>
                        {severitySlices.filter((slice) => slice.count > 0).map((slice) => (
                          <span
                            key={slice.key}
                            className="severity-stack-seg"
                            data-severity={slice.key}
                            style={{ flexGrow: slice.count }}
                            title={`${slice.label}: ${formatNumber(slice.count)}`}
                          />
                        ))}
                      </div>
                      <ul className="severity-bars" aria-label="Open findings per severity">
                        {severitySlices.map((slice) => (
                          <li key={slice.key} className="severity-bar" data-severity={slice.key} data-empty={slice.count === 0 ? 'true' : undefined}>
                            <span className="severity-bar-label">
                              <span className="severity-bar-swatch" aria-hidden="true" />
                              {slice.label}
                            </span>
                            <span className="severity-bar-count tabular-nums">{formatNumber(slice.count)}</span>
                            <span className="severity-bar-share tabular-nums" title={`${slice.label} share of open findings`}>{`${slice.share}%`}</span>
                          </li>
                        ))}
                      </ul>
                    </section>

                    <section className="risk-findings-aging" aria-labelledby="risk-aging-title">
                      <div className="risk-findings-head">
                        <h3 className="dash-subhead" id="risk-aging-title">Oldest open</h3>
                        <span className="risk-findings-total">{`${formatNumber(agingFindings.length)} of ${formatNumber(severityDist.total)} shown`}</span>
                      </div>
                      <ol className="aging-list">
                        {agingFindings.map((finding) => {
                          const id = getString(finding, ['id']);
                          const severityRaw = getString(finding, ['severity'], 'unknown');
                          return (
                            <li key={id || plainFindingTitle(finding, data.targets, data.checks)} className="aging-row">
                              <a className="aging-link" href={id ? buildDetailHref('finding-detail', id) : '#findings'}>
                                <span className="aging-title">{plainFindingTitle(finding, data.targets, data.checks)}</span>
                                <span className="aging-meta">
                                  <Badge tone={severityBadgeTone(severityRaw)} title={formatSeverityLabel(severityRaw)}>{severityShortLabel(severityRaw)}</Badge>
                                  {Number.isFinite(Date.parse(String(finding.created_at ?? ''))) ? (
                                    <>
                                      <span>{`Opened ${formatDate(finding.created_at)}`}</span>
                                      <span className="aging-age">{formatShortRelative(String(finding.created_at))}</span>
                                    </>
                                  ) : (
                                    <span>Open date not recorded</span>
                                  )}
                                </span>
                              </a>
                            </li>
                          );
                        })}
                      </ol>
                    </section>
                  </div>
                )}
              </CardContent>
            </Card>

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
                <CardDescription>Stored verdict posture by exhausted resource, target applicability, and 30-day evidence freshness.</CardDescription>
              </CardHeader>
              <CardContent>
                <ResourceMatrix
                  checks={data.checks}
                  targetGroups={data.targetGroups}
                  runs={data.runs}
                  evidence={data.evidence}
                  config={config}
                  session={session}
                  dataLoadError={[data.loadErrors.checks, data.loadErrors.targetGroups, data.loadErrors.runs, data.loadErrors.evidence].filter(Boolean).join(' ') || null}
                  onRefresh={onRefresh}
                />
              </CardContent>
            </Card>
          </div>
        </div>
      ) : null}
    </div>
  );
}

function severityBadgeTone(severity: string): UiBadgeTone {
  const key = severity.trim().toLowerCase();
  if (['s1', 'critical', 's2', 'high'].includes(key)) return 'danger';
  if (['s3', 'medium'].includes(key)) return 'warn';
  return 'muted';
}

/** Compact ownership label so the half-width posture table never clips its verdict column. */
function ownershipShortLabel(state: string): string {
  const key = state.trim().toLowerCase();
  if (['dns_verified'].includes(key)) return 'DNS verified';
  if (['provider_verified'].includes(key)) return 'Provider';
  if (['user_confirmed', 'verified'].includes(key)) return 'Verified';
  if (key.includes('pending') || key.includes('awaiting')) return 'Pending';
  return 'Unverified';
}

/** Single status word for the compact posture table; full verdict lives in the badge title. */
function postureVerdictLabel(status: EvidenceStatus): string {
  if (status === 'pass') return 'Pass';
  if (status === 'gap') return 'Gap';
  if (status === 'review') return 'Review';
  return 'No result';
}
