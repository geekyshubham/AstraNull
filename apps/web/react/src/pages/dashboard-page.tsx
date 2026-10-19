import { useEffect, useMemo, useState, type CSSProperties, type ReactNode } from 'react';
import { requestJson } from '../lib/api';
import { familyCoverageBuckets, inventoryUnits } from '../lib/domain-checks.mjs';
import { computeSubdomainGrouping, subdomainParentMap, topLevelAncestor } from '../lib/subdomain-grouping';
import { useOpenInspector } from '../components/evidence/use-inspector';
import {
  Activity,
  ArrowUpRight,
  Check,
  ChevronRight,
  Eye,
  ListChecks,
  RefreshCw,
  Target,
  TriangleAlert
} from 'lucide-react';
import { ReadinessPostureDonut } from '../components/charts/readiness-posture-donut';
import { ScoreTrend } from '../components/charts/score-trend';
import { CoverageTree } from '../components/charts/coverage-tree';
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
  buildSetupSteps,
  buildTargetPostureRows,
  EVIDENCE_STATUS_TONE,
  isTargetVerified,
  resolveRecentRuns,
  rollUpPostureRows,
  severityDistributionFromCounts,
  severityShortLabel,
  type EvidenceStatus,
  type SetupStep,
  type TargetPostureRow
} from '../lib/dashboard-metrics';
import { sessionHasPermission } from '../lib/dataset-access.mjs';
import { isFindingOpen } from '../lib/findings-helpers';
import { createFindingGroupIndex, findingGroupHref, groupFindings } from '../lib/finding-groups.mjs';
// @ts-ignore Plain ESM keeps run-start role parity testable with node:test.
import { canStartRun } from '../lib/run-permissions.mjs';
import { buildDetailHref } from '../lib/route-params';
import { routeTabs } from '../lib/prototype-manifest';
import type { BadgeTone, DataItem, PortalConfig, PortalData, ReadinessFactor, Session } from '../lib/types';
import { formatDate, formatNumber, formatSeverityLabel, pluralize, scoreTone } from '../lib/utils';
import { severityCountTone, severityTone } from '../lib/severity-tone';
// @ts-ignore Plain ESM keeps executive terminology directly testable with node:test.
import { dashboardReadinessMessage, plainFindingTitle, plainInlineText, plainVerdictLabel } from '../lib/plain-language.mjs';
import { PageHeader } from './page-components';
import { usePublishAssistantContext } from '../lib/assistant-page-store';
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

const STATUS_TONE: Readonly<Record<EvidenceStatus, UiBadgeTone>> = EVIDENCE_STATUS_TONE;

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

type NextStep = {
  kind: 'finding' | 'setup';
  key: string;
  title: string;
  detail: string;
  href: string;
  tone: UiBadgeTone;
  hasEvidence: boolean;
  findingId?: string;
  targetId?: string;
  checkId?: string;
};

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

function listValues(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

/** Finding rows only: `priority` is the server's most severe open findings; `findingsUnavailable` when their read failed. */
function buildNextSteps(data: PortalData, priority: DataItem[], findingsUnavailable: boolean): NextStep[] {
  if (findingsUnavailable) return [];
  const openFindings = priority
    .filter(isFindingOpen)
    .sort((left, right) => (FINDING_PRIORITY[getString(left, ['severity']).toLowerCase()] ?? 9) - (FINDING_PRIORITY[getString(right, ['severity']).toLowerCase()] ?? 9));
  return openFindings.slice(0, 3).map((finding, index) => {
    const id = getString(finding, ['id']);
    const severity = getString(finding, ['severity'], 'unknown');
    const title = fixTitle(finding, data.targets, data.checks);
    const plainTitle = plainFindingTitle(finding, data.targets, data.checks);
    const severityText = `${severityShortLabel(severity)} severity`;
    return {
      kind: 'finding',
      key: `finding-${id || index}`,
      title,
      detail: title === `Review ${plainTitle}` ? `${severityText} open finding` : `${severityText}: ${plainTitle}`,
      href: id ? buildDetailHref('finding-detail', id) : '#findings?status=open',
      tone: ['s1', 'critical', 's2', 'high'].includes(severity.toLowerCase()) ? 'danger' : 'warn',
      hasEvidence: listValues(finding.evidence_ids).filter(Boolean).length > 0,
      findingId: id || undefined,
      targetId: getString(finding, ['target_id']) || undefined,
      checkId: getString(finding, ['check_id']) || undefined
    };
  });
}

/* ---------- Weighted readiness factors (compact) ---------- */

const READINESS_SCALE = 100;

type FactorKind = 'scored' | 'penalty' | 'context';

type PendingGate = { requestId: string; label: string; missingArtifacts: number; approvals: number; packComplete: boolean };

function classifyFactor(factor: ReadinessFactor): FactorKind {
  const weight = factor.weight;
  if (typeof weight !== 'number' || !Number.isFinite(weight) || weight > 0) return 'scored';
  if (Number(factor.score) < 0) return 'penalty';
  return 'context';
}

function readPendingGates(state: PortalData['state']): PendingGate[] {
  const readiness = (state?.readiness ?? null) as DataItem | null;
  const governance = readiness?.governance && typeof readiness.governance === 'object' ? readiness.governance as DataItem : null;
  return listValues(governance?.pending_gates).flatMap((entry) => {
    if (!entry || typeof entry !== 'object') return [];
    const gate = entry as DataItem;
    const requestId = getString(gate, ['requestId', 'request_id']);
    if (!requestId) return [];
    const approvals = Number.isFinite(Number(gate.approvals)) ? Number(gate.approvals) : 0;
    const missingArtifacts = listValues(gate.missing_artifacts).length;
    const approvalGaps = approvals < 2 ? 1 : 0;
    return [{
      requestId,
      label: getString(gate, ['label'], 'High-scale request'),
      missingArtifacts,
      approvals,
      packComplete: typeof gate.pack_complete === 'boolean'
        ? gate.pack_complete
        : missingArtifacts === 0 && listValues(gate.missing).length <= approvalGaps
    }];
  });
}

function PendingGateLines({ gates }: { gates: PendingGate[] }) {
  if (gates.length === 0) return null;
  return (
    <ul className="factor-gates" aria-label="Pending high-scale gates">
      {gates.map((gate) => {
        const parts = [
          gate.missingArtifacts > 0
            ? `${formatNumber(gate.missingArtifacts)} authorization ${pluralize(gate.missingArtifacts, 'artifact')} missing`
            : gate.packComplete ? '' : 'Authorization pack incomplete',
          `SOC approvals ${gate.approvals}/2`
        ].filter(Boolean);
        return (
          <li key={gate.requestId}>
            <span>{`High-scale request "${gate.label}": ${parts.join(' · ')}`}</span>
            <a href={buildDetailHref('queue-detail', gate.requestId)} aria-label={`Review high-scale request ${gate.label}`}>Review request</a>
          </li>
        );
      })}
    </ul>
  );
}

function FactorRow({ factor, gates }: { factor: ReadinessFactor; gates: PendingGate[] }) {
  const key = getString(factor as DataItem, ['key']);
  const label = plainInlineText(getString(factor as DataItem, ['label', 'key'], 'Factor'));
  const score = Number(factor.score);
  const kind = classifyFactor(factor);
  const detail = plainInlineText(getString(factor as DataItem, ['detail', 'reason']));
  const extra = key === 'soc_readiness' ? <PendingGateLines gates={gates} /> : null;
  if (kind === 'scored') {
    const scale = typeof factor.weight === 'number' && Number.isFinite(factor.weight) && factor.weight > 0 ? factor.weight : READINESS_SCALE;
    const share = Math.min(100, Math.max(0, (score / scale) * 100));
    return (
      <div className="factor-row" data-kind="scored" data-testid="readiness-factor-row">
        <span className="factor-name" title={`${label}: ${score} of ${scale} points, from GET /v1/state readiness.factors`}>{label}</span>
        <span className="factor-score">{score}/{scale}</span>
        <span className="factor-track" role="img" aria-label={`${label} scored ${score} of ${scale} points`}>
          <span className="factor-fill" data-tone={scoreTone(share)} style={{ '--factor-share': share / 100 } as CSSProperties} />
        </span>
        {detail ? <p className="factor-detail">{detail}</p> : null}
        {extra}
      </div>
    );
  }
  if (kind === 'penalty') {
    const points = Math.abs(score);
    return (
      <div className="factor-row" data-kind="penalty" data-deducted="true" data-testid="readiness-factor-row">
        <span className="factor-name">{label}</span>
        <span className="factor-score" role="img" aria-label={`${label}: penalty of ${points} points`}>{`\u2212${points} pts`}</span>
        {detail ? <p className="factor-detail">{detail}</p> : null}
        {extra}
      </div>
    );
  }
  return (
    <div className="factor-row" data-kind="context" data-testid="readiness-factor-row">
      <span className="factor-name">{label}</span>
      <span className="factor-score">Not scored</span>
      {detail ? <p className="factor-detail">{detail}</p> : null}
      {extra}
    </div>
  );
}

function WeightedFactors({ factors, publishedScore, gates }: { factors: ReadinessFactor[]; publishedScore: number | null; gates: PendingGate[] }) {
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
  const scoring = rows.filter((factor) => classifyFactor(factor) !== 'context');
  const context = rows.filter((factor) => classifyFactor(factor) === 'context');
  return (
    <div className="an-factor-list" data-testid="readiness-factors">
      {scoring.map((factor, index) => <FactorRow key={getString(factor as DataItem, ['key']) || `scoring-${index}`} factor={factor} gates={gates} />)}
      {context.length > 0 ? (
        <section className="factor-context" aria-labelledby="dash-factor-context-title">
          <h4 className="factor-context-title" id="dash-factor-context-title">Context (not part of the score)</h4>
          {context.map((factor, index) => <FactorRow key={getString(factor as DataItem, ['key']) || `context-${index}`} factor={factor} gates={gates} />)}
        </section>
      ) : null}
      {publishedScore !== null ? (
        <p className="factor-total" data-testid="readiness-published-score">
          <span>Published score</span>
          <strong className="tabular-nums">{publishedScore}/100</strong>
        </p>
      ) : null}
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
  const title = family === 'waf' ? 'WAF' : 'CDN';
  if (result.state === 'loading') return <div className="coverage-row" aria-busy="true"><span className="coverage-title">{title}</span><div className="skeleton skeleton-row" /></div>;
  const buckets = result.state === 'ready' ? familyCoverageBuckets(result.payload) : null;
  if (!buckets || !buckets.complete || !buckets.denominator) {
    const reason = result.state === 'unsupported' ? 'Not reported by this server.'
      : result.state === 'denied' ? 'Your role cannot read target analytics.'
        : result.state === 'error' ? 'Could not load.'
          : !buckets?.complete ? 'Scope could not be read completely.' : 'No hosts declared yet.';
    return (
      <div className="coverage-row">
        <span className="coverage-title">{title}</span>
        <span className="coverage-unavailable">{reason}{result.state === 'error' ? <> <Button size="sm" variant="ghost" onClick={onRetry}>Retry</Button></> : null}</span>
      </div>
    );
  }
  const detected = buckets.parts.find((part) => part.group === 'detected');
  const notDetected = buckets.parts.find((part) => part.group === 'not_detected');
  const unknownParts = buckets.parts.filter((part) => part.group !== 'detected' && part.group !== 'not_detected' && part.count > 0);
  const unknownCount = unknownParts.reduce((sum, part) => sum + part.count, 0);
  const segments = [
    { key: 'detected', label: 'Detected', count: detected?.count ?? 0, href: detected?.href ?? '' },
    { key: 'not_detected', label: 'Not detected', count: notDetected?.count ?? 0, href: notDetected?.href ?? '' },
    { key: 'unmeasured', label: 'Unknown', count: unknownCount, href: unknownParts.length === 1 ? unknownParts[0].href : '' }
  ];
  const unknownDetail = unknownParts.map((part) => `${part.label} ${formatNumber(part.count)}`).join(' · ');
  return (
    <div className="coverage-row">
      <span className="coverage-title">{title}</span>
      <span className="coverage-bar" role="img" aria-label={`${title}: ${segments.map((part) => `${part.label} ${part.count}`).join(', ')}, of ${buckets.denominator} hosts`}>
        {segments.filter((part) => part.count > 0).map((part) => <span key={part.key} className="coverage-seg" data-segment={part.key} style={{ flexGrow: part.count }} />)}
      </span>
      <ul className="coverage-stats">
        {segments.map((part) => {
          const body = (
            <>
              <span className="coverage-swatch" data-segment={part.key} aria-hidden="true" />
              <strong className="tabular-nums">{formatNumber(part.count)}</strong>
              <span>{part.label}</span>
            </>
          );
          return (
            <li key={part.key} data-segment={part.key}>
              {part.href && part.count > 0 ? (
                <a href={part.href} aria-label={`${title} ${part.label.toLowerCase()}: ${formatNumber(part.count)} hosts. Open the list.`}>{body}</a>
              ) : (
                <span title={part.key === 'unmeasured' && unknownDetail ? unknownDetail : undefined}>{body}</span>
              )}
            </li>
          );
        })}
      </ul>
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

function readinessRecordPosture(state: PortalData['state']): DataItem | null {
  const readiness = (state?.readiness ?? null) as DataItem | null;
  return readiness?.posture && typeof readiness.posture === 'object' && !Array.isArray(readiness.posture) ? readiness.posture as DataItem : null;
}

function finiteCount(value: unknown) {
  return typeof value === 'number' && Number.isFinite(value) && value >= 0 ? value : null;
}

function DeclaredHostCoverage({ waf, cdn, total, onRetry }: { waf: CoverageResult; cdn: CoverageResult; total: number | null; onRetry: () => void }) {
  return (
    <section className="declared-coverage" aria-labelledby="declared-coverage-title">
      <div className="declared-coverage-head">
        <h2 id="declared-coverage-title">WAF and CDN detection</h2>
        <p>{total !== null ? `Across ${formatNumber(total)} declared ${pluralize(total, 'host')}` : 'Across your declared hosts'}</p>
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

  const publishedScore = typeof data.state?.readiness?.score === 'number' ? data.state.readiness.score : null;
  const scoreStatus = getString((data.state?.readiness ?? null) as DataItem | null, ['score_status']);
  const pendingGates = readPendingGates(data.state);
  const readinessFactors = Array.isArray(data.state?.readiness?.factors) ? data.state!.readiness!.factors! : [];
  const openInspector = useOpenInspector();
  // Finding counts on this page are server predicates, never the shell's first loaded page.
  const [findingsReload, setFindingsReload] = useState(0);
  const coverageUnit: CoverageUnit = 'normalized_hostname';
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
  // Subdomains are grouped under their parent domain, so the scope counts below report
  // only top-level domains rather than every discovered subdomain (display-only).
  const subdomainGrouping = computeSubdomainGrouping(data.targets);
  const subdomainParents = useMemo(() => subdomainParentMap(data.targets), [data.targets]);
  const topLevelOf = (id: string) => topLevelAncestor(id, subdomainParents);
  const isTopLevelTarget = (target: DataItem) => !subdomainGrouping.hiddenIds.has(getString(target, ['id'], ''));
  const isTopLevelRow = (row: { id: string }) => !subdomainGrouping.hiddenIds.has(row.id);
  const topLevelTargetList = data.targets.filter(isTopLevelTarget);
  const units = inventoryUnits(topLevelTargetList);
  const recentRuns = resolveRecentRuns(data, 6);
  const findingSteps = buildNextSteps(data, openOverview.priority, countsUnavailable || (openOverview.state === 'error' && openOverview.priority.length === 0));
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
  const declaredTargets = loadedIsWholeScope ? topLevelTargetList.length : (serverRecords ?? data.targets.length);
  const distinctHosts = loadedIsWholeScope ? units.distinctHosts : (serverHosts ?? units.distinctHosts);
  const verifiedTargets: number | null = loadedIsWholeScope ? topLevelTargetList.filter(isTargetVerified).length : serverVerified;
  const verifiedShare = declaredTargets > 0 && verifiedTargets !== null ? Math.round((verifiedTargets / declaredTargets) * 100) : null;

  // Each domain row folds in its subdomains, so a result recorded on a subdomain counts for its domain.
  const allPostureRows = rollUpPostureRows(buildTargetPostureRows(data, undefined, { openFindings: sampleRows, openCounts }), topLevelOf).filter(isTopLevelRow);
  const postureRows = allPostureRows.slice(0, 6);
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

  // No score without evidence: none in loaded runs, none in the server's own posture, and no open finding.
  const serverPosture = readinessRecordPosture(data.state);
  const serverMeasured = (finiteCount(serverPosture?.pass) ?? 0) + (finiteCount(serverPosture?.gap) ?? 0) + (finiteCount(serverPosture?.review) ?? 0);
  const evidenceMissing = !coverageUnavailable && targetsWithEvidence === 0 && serverMeasured === 0 && (openOverview.total ?? 0) === 0;
  const noEvidence = evidenceMissing || scoreStatus === 'not_applicable' || scoreStatus === 'incomplete_inputs';
  const score = noEvidence ? null : publishedScore;
  const setupSteps: SetupStep[] = data.loadErrors.runs ? [] : buildSetupSteps(data, !evidenceMissing, buildDetailHref);
  const currentSetupIndex = setupSteps.findIndex((step) => step.state === 'current');
  const priorityFixesUnavailable = countsUnavailable || (openOverview.state === 'error' && severity.total > 0);
  const showSetup = findingSteps.length === 0 && currentSetupIndex >= 0 && !priorityFixesUnavailable;
  const findingBadgeTone: UiBadgeTone = findingSteps.some((step) => step.tone === 'danger') ? 'danger' : 'warn';
  const canWriteTargets = sessionHasPermission(session, 'target_group:write');
  const canRunChecks = canStartRun(session.role);
  const setupStepAllowed: Record<SetupStep['key'], boolean> = {
    'declare-target': canWriteTargets,
    'verify-ownership': canRunChecks,
    'first-run': canRunChecks
  };
  const needsFirstTarget = !targetsUnavailable && declaredTargets === 0;

  const lastValidationIso = getString(data.state ?? {}, ['last_validation_at'])
    || (recentRuns[0] ? String(recentRuns[0].completed_at ?? recentRuns[0].started_at ?? recentRuns[0].created_at ?? '') : '');
  const lastValidationLabel = data.loadErrors.runs ? UNAVAILABLE : lastValidationIso ? formatShortRelative(lastValidationIso) : 'Never';

  const highPriorityOpen = severity.critical + severity.high;
  const executive = dashboardReadinessMessage({
    score: noEvidence ? 0 : score,
    highPriorityFindings: highPriorityOpen,
    coveragePercent,
    dataUnavailable: Boolean(data.error || data.loadErrors.targets || data.loadErrors.runs || data.loadErrors.evidence || countsUnavailable),
    hasEvidence: !noEvidence
  });

  const killSwitch = data.state?.kill_switch ?? null;
  const killSwitchActive = killSwitch?.active === true;
  const killSwitchReason = getString((killSwitch ?? {}) as DataItem, ['reason']);
  const killSwitchUpdatedAt = getString((killSwitch ?? {}) as DataItem, ['updated_at']);

  const postureColumns: TableColumn<TargetPostureRow>[] = [
    {
      key: 'target',
      label: 'Target',
      render: (row) => (
        <span className="posture-target">
          <strong title={row.value}>
            {row.id
              ? <a className="detail-entity-link" href={buildDetailHref('target-detail', row.id)} onClick={(event) => event.stopPropagation()}>{row.value}</a>
              : row.value}
          </strong>
          <PostureMeta row={row} />
        </span>
      )
    },
    {
      key: 'verdict',
      label: 'Recorded verdict',
      render: (row) => (
        <span className="posture-verdict">
          <Badge
            tone={STATUS_TONE[row.verdictStatus]}
            title={(row.hostCount ?? 1) > 1
              ? `Worst result across ${formatNumber(row.hostCount ?? 1)} hosts in this domain; ${formatNumber(row.testedHostCount ?? 0)} have a result.`
              : row.verdict
                ? `${plainVerdictLabel(row.verdict)}${row.verdictRunId ? ` (run ${row.verdictRunId})` : ''}`
                : row.verdictBasis === 'unbacked' ? 'A run finished without a recorded verdict or evidence, so it is not counted.' : 'No evidence-backed verdict yet'}
          >
            {row.verdictStatus === 'none' && row.verdictBasis === 'unbacked'
              ? 'Not recorded'
              : row.openFindings > 0 && row.verdictStatus !== 'pass'
                ? `${postureVerdictLabel(row.verdictStatus)} · ${formatNumber(row.openFindings)} open`
                : postureVerdictLabel(row.verdictStatus)}
          </Badge>
        </span>
      )
    },
    {
      key: 'verification',
      label: 'Ownership',
      render: (row) => <VerifyChip state={row.verificationState} />
    }
  ];

  function rowProps(route: string, id: string) {
    if (!id) return {};
    const href = buildDetailHref(route, id);
    const navigate = () => {
      const hashIndex = href.indexOf('#');
      window.location.hash = hashIndex >= 0 ? href.slice(hashIndex + 1) : href;
    };
    return {
      style: { cursor: 'pointer' as const },
      onClick: () => { navigate(); }
    };
  }

  // Oldest open issues: identical findings across subdomains collapse into one group, oldest first.
  const agingGroups = useMemo(() => {
    const seen = new Set<string>();
    const rows = [...openOverview.oldest, ...sampleRows].filter((finding) => {
      const id = getString(finding, ['id']);
      if (!isFindingOpen(finding) || (id && seen.has(id))) return false;
      if (id) seen.add(id);
      return true;
    });
    const index = createFindingGroupIndex({ targets: data.targets, checks: data.checks });
    return groupFindings(rows, index)
      .sort((left, right) => String(left.earliestOpenedAt ?? '9999').localeCompare(String(right.earliestOpenedAt ?? '9999')))
      .slice(0, 6);
  }, [openOverview.oldest, sampleRows, data.targets, data.checks]);

  // Severity split for the risk-trends findings panel from exact server counts per severity.
  const severityDist = severityDistributionFromCounts(openOverview.severity ?? { critical: 0, high: 0, medium: 0, low: 0, unrecorded: 0 });
  const severitySlices = severityDist.slices.filter((slice) => slice.key !== 'unrecorded' || slice.count > 0);
  const severityStackLabel = `${formatNumber(severityDist.total)} open ${pluralize(severityDist.total, 'finding')}: ${severitySlices
    .map((slice) => `${slice.label} ${formatNumber(slice.count)}`)
    .join(', ')}`;

  usePublishAssistantContext({
    route: 'dashboard',
    tab,
    facts: {
      'Readiness score': score === null ? 'Not scored yet' : `${score}/100`,
      'Open findings': openOverview.total ?? undefined,
      'Critical open': openOverview.total === null ? undefined : severity.critical,
      'High open': openOverview.total === null ? undefined : severity.high,
      'Declared targets': targetsUnavailable ? undefined : declaredTargets,
      'Ownership verified': verifiedTargets ?? undefined,
      'Targets with results': coveragePercent === null ? undefined : `${targetsWithEvidence} (${coveragePercent}%)`,
      ...Object.fromEntries(postureTally.map((item) => [`Targets ${item.status === 'none' ? 'without results' : `with ${item.status}`}`, item.count])),
      'Last validation': lastValidationLabel,
      'Kill switch': killSwitchActive ? 'Active' : undefined,
    },
  });
  return (
    <div className="content dashboard-page">
      <PageHeader
        route="dashboard"
        title="Readiness overview"
        description="Every verdict below traces to observed probe evidence or an explicit customer declaration. Validation runs from the outside in."
        actions={
          <>
            <Button type="button" variant="secondary" size="sm" loading={refreshing} onClick={() => void handleRefresh()}>
              <RefreshCw size={15} aria-hidden="true" /> Refresh
            </Button>
            {needsFirstTarget ? (
              canWriteTargets ? <AnchorButton href="#targets?add=1" variant="default" size="sm">Add target</AnchorButton> : null
            ) : canStartRun(session.role) ? (
              <AnchorButton href="#targets" variant="default" size="sm">Validate a target</AnchorButton>
            ) : null}
          </>
        }
      />
      <Tabs
        value={tab}
        options={tabOptions}
        onChange={handleTabChange}
        className="tabs-wrap"
        ariaLabel="Dashboard sections"
        getTabId={(id) => `dashboard-sections-tab-${id}`}
        getPanelId={(id) => `dashboard-sections-panel-${id}`}
      />

      {killSwitchActive ? (
        <div className="form-banner error stack-tight" role="alert">
          <strong>AstraNull SOC has paused testing for this workspace</strong>
          <span>New validation runs and scans are blocked, and runs in progress were cancelled. Contact support for status.</span>
          {killSwitchReason ? <span title="Kill switch reason from GET /v1/state kill_switch.reason">{`Reason: ${killSwitchReason}`}</span> : null}
          {killSwitchUpdatedAt ? <span title="Kill switch updated_at from GET /v1/state kill_switch.updated_at">Paused {formatDate(killSwitchUpdatedAt)}</span> : null}
        </div>
      ) : null}

      {tab === 'overview' ? (
        <div role="tabpanel" id="dashboard-sections-panel-overview" aria-labelledby="dashboard-sections-tab-overview" className="tab-panel dashboard-overview">
          <div className="dashboard-kpis" role="group" aria-label="Readiness key metrics">
            <KpiCard
              label="Readiness"
              value={score !== null
                ? <><span className="dashboard-kpi-score">{score}</span><span className="unit">/100</span></>
                : <span className="dashboard-kpi-score"><span aria-hidden="true">—</span><span className="sr-only">No published score</span></span>}
              sub={<span className="dashboard-kpi-sub" title={score === null ? executive.detail : 'Published workspace score from evidence in the last 30 days. Not a protection guarantee.'}>{executive.headline}</span>}
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
              sub={<span className="dashboard-kpi-sub">{targetsUnavailable ? 'Target data unavailable' : declaredTargets === 0 ? 'No targets declared yet' : `${formatNumber(distinctHosts)} distinct ${pluralize(distinctHosts, 'hostname')} · ${verifiedTargets === null ? 'ownership verified count loading' : `${formatNumber(verifiedTargets)} ownership verified (${verifiedShare}%)`}`}</span>}
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
                  <Badge tone={severityCountTone('critical', severity.critical)} title="Severity 1 (Critical)">{formatNumber(severity.critical)} critical</Badge>
                  <Badge tone={severityCountTone('high', severity.high)} title="Severity 2 (High)">{formatNumber(severity.high)} high</Badge>
                </span>
              )}
              href="#findings?status=open"
              actionLabel="Open the open findings queue"
            />
          </div>

          <div className="an-dash-grid">
            <div className="dash-area-coverage">
              <DeclaredHostCoverage waf={wafCoverage} cdn={cdnCoverage} total={wafCoverage.state === 'ready' ? familyCoverageBuckets(wafCoverage.payload).denominator : null} onRetry={() => setCoverageReload((value) => value + 1)} />
            </div>
            <Card className="dash-area-readiness">
              <CardHeader>
                <div>
                  <CardTitle>Why this readiness score</CardTitle>
                  <CardDescription>Latest evidence-backed result per check across loaded runs, and the weighted factors behind the published score. A passing check covers its own scenario only{highPriorityOpen > 0 ? `; ${formatNumber(highPriorityOpen)} high-priority ${pluralize(highPriorityOpen, 'finding')} ${highPriorityOpen === 1 ? 'remains' : 'remain'} open` : ''}.</CardDescription>
                </div>
              </CardHeader>
              <CardContent>
                {noEvidence ? (
                  <EmptyState
                    icon={Activity}
                    title="No evidence-backed verdicts yet."
                    body="Check verdicts and weighted factors appear after the first bounded check publishes a verdict."
                  />
                ) : (
                  <div className="readiness-split">
                    <section className="readiness-split-pane" aria-labelledby="dash-posture-breakdown-title">
                      <h3 className="dash-subhead" id="dash-posture-breakdown-title">Check verdicts</h3>
                      <ReadinessPostureDonut state={data.state} runs={data.runs} checks={data.checks} />
                    </section>
                    <section className="readiness-split-pane" aria-labelledby="dash-weighted-factors-title">
                      <h3 className="dash-subhead" id="dash-weighted-factors-title">Weighted factors</h3>
                      <p className="dash-subhead-note">Scored factors add points and penalties subtract them; context factors are shown for transparency and do not change the score.</p>
                      <WeightedFactors factors={readinessFactors} publishedScore={publishedScore} gates={pendingGates} />
                    </section>
                  </div>
                )}
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
                  className="dash-posture-table"
                  columns={postureColumns}
                  items={postureRows}
                  loadError={[data.loadErrors.targets, data.loadErrors.runs].filter(Boolean).join(' ') || null}
                  onRetry={() => void onRefresh()}
                  getRowId={(row) => row.id}
                  getRowProps={(row) => rowProps('target-detail', row.id)}
                  empty={<EmptyState icon={Target} title="No targets declared yet." body="Declare a domain, hostname, IP, or URL to start validating readiness." actionHref={canWriteTargets ? '#targets?add=1' : '#targets'} actionLabel={canWriteTargets ? 'Add target' : 'Open targets'} />}
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
                  <CardTitle>{showSetup ? 'Get started' : 'What to fix first'}</CardTitle>
                  <CardDescription>
                    {showSetup
                      ? 'Three steps before AstraNull has evidence: declare a target, prove ownership, run a bounded check.'
                      : 'Highest-severity open findings first. View evidence shows what was recorded for each one.'}
                  </CardDescription>
                </div>
                {findingSteps.length > 0
                  ? <Badge tone={findingBadgeTone}>{`${formatNumber(findingSteps.length)} open`}</Badge>
                  : showSetup ? <Badge tone="muted">{`Step ${currentSetupIndex + 1} of ${setupSteps.length}`}</Badge> : null}
              </CardHeader>
              <CardContent>
                {findingSteps.length > 0 ? (
                  <ol className="fix-list">
                    {findingSteps.map((step, index) => (
                      <li className="fix-row" key={step.key}>
                        <span className="fix-rank" data-tone={step.tone} aria-hidden="true">{index + 1}</span>
                        <span className="fix-copy">
                          <strong>{step.title}</strong>
                          <span>{step.detail}</span>
                          {step.hasEvidence ? null : <span className="fix-evidence"><Badge tone="warn">No evidence recorded</Badge></span>}
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
                            <AnchorButton href={step.href} variant="secondary" size="sm" aria-label={`Open finding for ${step.title}`}>Open finding<ArrowUpRight size={14} aria-hidden="true" /></AnchorButton>
                          </span>
                        ) : (
                          <AnchorButton href={step.href} variant="secondary" size="sm" aria-label={`Open ${step.title}`}>Open</AnchorButton>
                        )}
                      </li>
                    ))}
                  </ol>
                ) : showSetup ? (
                  <ol className="fix-list setup-list" aria-label="Setup steps">
                    {setupSteps.map((step, index) => (
                      <li className="fix-row setup-row" data-state={step.state} data-locked={step.state === 'current' && !setupStepAllowed[step.key] ? 'true' : undefined} key={step.key} aria-current={step.state === 'current' ? 'step' : undefined}>
                        <span className="fix-rank" data-state={step.state} aria-hidden="true">
                          {step.state === 'done' ? <Check size={14} /> : index + 1}
                        </span>
                        {step.state === 'current' ? (
                          <>
                            <span className="fix-copy">
                              <strong>{step.title}</strong>
                              <span>{step.detail}</span>
                              {setupStepAllowed[step.key] ? null : (
                                <span className="setup-role-note" data-testid="setup-step-role-note">Your role cannot do this step. Ask a workspace admin to complete it.</span>
                              )}
                            </span>
                            {setupStepAllowed[step.key] ? <AnchorButton href={step.href} variant="default" size="sm">{step.ctaLabel}</AnchorButton> : null}
                          </>
                        ) : (
                          <span className="fix-copy setup-muted">
                            <span>{step.state === 'done' ? `Done: ${step.title}` : `Then: ${step.title}`}</span>
                          </span>
                        )}
                      </li>
                    ))}
                  </ol>
                ) : priorityFixesUnavailable ? (
                  <EmptyState icon={TriangleAlert} title="Priority fixes unavailable." body="Findings did not load, so AstraNull cannot rank what to fix first." actionLabel="Retry" onAction={() => setFindingsReload((value) => value + 1)} />
                ) : (
                  <EmptyState icon={ListChecks} title="No open finding needs a fix." body="Keep scheduled validation current so new evidence-backed gaps surface here first." />
                )}
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
                        <h3 className="dash-subhead" id="risk-aging-title">Oldest open issues</h3>
                        <span className="risk-findings-total">{`${formatNumber(agingGroups.length)} ${pluralize(agingGroups.length, 'issue')}`}</span>
                      </div>
                      <ol className="aging-list">
                        {agingGroups.map((group) => {
                          const severityRaw = group.severity || 'unknown';
                          const targets = group.openAssetCount;
                          return (
                            <li key={group.key} className="aging-row">
                              <a className="aging-link" href={findingGroupHref(group.key)}>
                                <span className="aging-title">{group.title}</span>
                                <span className="aging-meta">
                                  <Badge tone={severityTone(severityRaw)} title={formatSeverityLabel(severityRaw)}>{severityShortLabel(severityRaw)}</Badge>
                                  <span>{`${formatNumber(targets)} ${pluralize(targets, 'target')}${sampleComplete ? '' : '+'}`}</span>
                                  {group.earliestOpenedAt ? (
                                    <span className="aging-age" title={`Oldest opened ${formatDate(group.earliestOpenedAt)}`}>{formatShortRelative(group.earliestOpenedAt)}</span>
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
                <div>
                  <CardTitle>Coverage by domain</CardTitle>
                  <CardDescription>Latest evidence-backed result per domain. Expand a domain to see its subdomains.</CardDescription>
                </div>
              </CardHeader>
              <CardContent>
                <CoverageTree
                  checks={data.checks}
                  targets={data.targets}
                  runs={data.runs}
                  evidence={data.evidence}
                  openFindings={sampleRows}
                  loadError={[data.loadErrors.checks, data.loadErrors.targets, data.loadErrors.runs].filter(Boolean).join(' ') || null}
                  onRetry={() => void onRefresh()}
                />
              </CardContent>
            </Card>
          </div>
        </div>
      ) : null}
    </div>
  );
}

/** Subdomain count and one tag; a `domain:` tag that repeats the hostname is dropped. */
function PostureMeta({ row }: { row: TargetPostureRow }) {
  const tags = row.tags.filter((tag) => tag.toLowerCase() !== `domain:${row.value.toLowerCase()}`);
  const subdomains = Math.max(0, (row.hostCount ?? 1) - 1);
  if (!tags.length && !subdomains) return null;
  return (
    <span className="posture-meta">
      {subdomains ? <span>{`${formatNumber(subdomains)} ${pluralize(subdomains, 'subdomain')}`}</span> : null}
      {tags.length ? <span className="posture-tag" title={tags.join(', ')}>{tags[0]}</span> : null}
      {tags.length > 1 ? <span className="posture-tag posture-tag-more" title={tags.join(', ')}>{`+${tags.length - 1}`}</span> : null}
    </span>
  );
}

/** Single status word for the compact posture table; full verdict lives in the badge title. */
function postureVerdictLabel(status: EvidenceStatus): string {
  if (status === 'pass') return 'Pass';
  if (status === 'gap') return 'Gap';
  if (status === 'review') return 'Review';
  return 'No result';
}
