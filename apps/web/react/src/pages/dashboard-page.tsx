import { useEffect, useState, type KeyboardEvent as ReactKeyboardEvent } from 'react';
import {
  Activity,
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
import { EvidenceGuide } from '../components/ui/evidence-guide';
import { AnchorButton, Button } from '../components/ui/button';
import { Tabs } from '../components/ui/tabs';
import { DataTable, type TableColumn } from '../components/ui/table';
import { VerifyChip } from '../lib/verify-chip';
import {
  buildDefensePath,
  buildTargetPostureRows,
  classifyVerdict,
  findingSeverityBuckets,
  overallDefenseStatus,
  resolveRecentRuns,
  type DefensePathStage,
  type EvidenceStatus,
  type TargetPostureRow
} from '../lib/dashboard-metrics';
import { isFindingOpen } from '../lib/findings-helpers';
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
  if (!Number.isFinite(ts)) return '—';
  const seconds = Math.round(Math.max(0, Date.now() - ts) / 1000);
  if (seconds < 60) return `${seconds}s ago`;
  const minutes = Math.round(seconds / 60);
  if (minutes < 120) return `${minutes}m ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 48) return `${hours}h ago`;
  return `${Math.round(hours / 24)}d ago`;
}

/* ---------- Prioritized fixes (evidence-backed, no agent step) ---------- */

const FINDING_PRIORITY: Record<string, number> = {
  s1: 0, critical: 0, s2: 1, high: 1, s3: 2, medium: 2, s4: 3, low: 3
};

type NextStep = { key: string; title: string; detail: string; href: string; tone: UiBadgeTone };

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
  if (context.includes('authorization') || context.includes('approval')) return `Complete SOC authorization for ${targetName}`;
  return `Review ${plainFindingTitle(finding, targets, checks)}`;
}

function buildNextSteps(data: PortalData): NextStep[] {
  const steps: NextStep[] = [];
  const activeGroups = data.targetGroups.filter((group) => group.archived_at == null);
  const hasEvidence = data.runs.some((run) => {
    const status = getString(run, ['status']).toLowerCase();
    const verdict = typeof run.verdict === 'string' ? run.verdict : getString(run.verdict as DataItem, ['verdict', 'status']);
    return ['completed', 'verdicted', 'finalized'].includes(status) && classifyVerdict(verdict) !== 'none';
  });
  const openFindings = data.findings
    .filter(isFindingOpen)
    .sort((left, right) => {
      const lr = FINDING_PRIORITY[getString(left, ['severity']).toLowerCase()] ?? 9;
      const rr = FINDING_PRIORITY[getString(right, ['severity']).toLowerCase()] ?? 9;
      if (lr !== rr) return lr - rr;
      return String(left.created_at ?? left.id ?? '').localeCompare(String(right.created_at ?? right.id ?? ''));
    });

  if (!data.loadErrors.findings) {
    for (const finding of openFindings.slice(0, 3)) {
      const id = getString(finding, ['id']);
      const severity = getString(finding, ['severity'], 'unknown');
      steps.push({
        key: `finding-${id || steps.length}`,
        title: fixTitle(finding, data.targets, data.checks),
        detail: `${formatSeverityLabel(severity)} · ${plainFindingTitle(finding, data.targets, data.checks)}`,
        href: id ? buildDetailHref('finding-detail', id) : '#findings',
        tone: ['s1', 'critical', 's2', 'high'].includes(severity.toLowerCase()) ? 'danger' : 'warn'
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
      href: '#targets',
      tone: 'info'
    });
  }
  if (steps.length < 3 && !data.loadErrors.runs && !hasEvidence && activeGroups.length > 0) {
    steps.push({
      key: 'first-run',
      title: 'Run the first bounded validation',
      detail: 'Complete at least one safe check to create readiness evidence.',
      href: '#runs',
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

/* ---------- Defense path strip (the one bold element) ---------- */

const OVERALL_LABEL: Record<EvidenceStatus, string> = {
  pass: 'Every stage has passing evidence',
  gap: 'At least one stage has a gap',
  review: 'Incomplete or mixed evidence',
  none: 'No evidence yet'
};

const STATUS_LABEL: Record<EvidenceStatus, string> = { pass: 'Pass', gap: 'Gap', review: 'Review', none: 'Not measured' };

function DefensePathStrip({ stages }: { stages: DefensePathStage[] }) {
  const overall = overallDefenseStatus(stages);
  return (
    <section className="defense-path" aria-labelledby="defense-path-title">
      <div className="defense-path-head">
        <div>
          <h2 id="defense-path-title">Where does attack traffic get stopped?</h2>
          <p>Each stage shows the evidence AstraNull has for the path a request takes, from the open internet to your origin.</p>
        </div>
        <span className="defense-path-verdict">
          Path status
          <Badge tone={STATUS_TONE[overall]}>{OVERALL_LABEL[overall]}</Badge>
        </span>
      </div>
      <div className="defense-path-track" role="list" aria-label="Outside-in defense path stages">
        {stages.map((stage) => (
          <div className="defense-stage" data-status={stage.status} role="listitem" key={stage.key}>
            <div className="defense-stage-top">
              <span className="defense-stage-label">{stage.label}</span>
              <span className="defense-stage-dot" data-status={stage.status} aria-hidden="true" />
            </div>
            <span className="defense-stage-headline">{stage.headline}</span>
            <p className="defense-stage-detail">{stage.detail}</p>
            <Badge tone={STATUS_TONE[stage.status]} title={stage.detail}>
              {stage.unavailable ? 'Data unavailable' : STATUS_LABEL[stage.status]}
            </Badge>
          </div>
        ))}
      </div>
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
    try {
      await onRefresh();
    } finally {
      setRefreshing(false);
    }
  }

  const score = typeof data.state?.readiness?.score === 'number' ? data.state.readiness.score : null;
  const readinessFactors = Array.isArray(data.state?.readiness?.factors) ? data.state!.readiness!.factors! : [];
  const defensePath = buildDefensePath(data);
  const recentRuns = resolveRecentRuns(data, 6);
  const postureRows = buildTargetPostureRows(data, 6);
  const nextSteps = buildNextSteps(data);
  const severity = findingSeverityBuckets(data.findings);

  const targetsUnavailable = Boolean(data.loadErrors.targets);
  const verifiedTargets = data.targets.filter(isTargetVerified).length;
  const declaredTargets = data.targets.length;
  const verifiedShare = declaredTargets > 0 ? Math.round((verifiedTargets / declaredTargets) * 100) : null;

  // Evidence coverage: declared targets with at least one evidence-backed verdict.
  const targetsWithEvidence = new Set(
    buildTargetPostureRows(data).filter((row) => row.verdictStatus !== 'none').map((row) => row.id)
  ).size;
  const coverageUnavailable = targetsUnavailable || Boolean(data.loadErrors.runs);
  const coveragePercent = coverageUnavailable || declaredTargets === 0 ? null : Math.round((targetsWithEvidence / declaredTargets) * 100);

  const lastValidationIso = getString(data.state ?? {}, ['last_validation_at'])
    || (recentRuns[0] ? String(recentRuns[0].completed_at ?? recentRuns[0].started_at ?? recentRuns[0].created_at ?? '') : '');
  const lastValidationLabel = data.loadErrors.runs ? '—' : lastValidationIso ? formatShortRelative(lastValidationIso) : 'Never';

  const executive = dashboardReadinessMessage({
    score,
    highPriorityFindings: severity.critical + severity.high,
    coveragePercent,
    dataUnavailable: Boolean(data.error || data.loadErrors.targets || data.loadErrors.runs || data.loadErrors.evidence || data.loadErrors.findings)
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
      label: 'Latest verdict',
      render: (row) => (
        <Badge tone={STATUS_TONE[row.verdictStatus]} title={row.verdict ? plainVerdictLabel(row.verdict) : 'No evidence-backed verdict yet'}>
          {row.verdict
            ? row.openFindings > 0 && classifyVerdict(row.verdict) === 'pass'
              ? `Passed · ${row.openFindings} open`
              : postureVerdictLabel(row.verdictStatus)
            : 'No result'}
        </Badge>
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
          <small className="mono">{getString(item, ['id'], '—')}</small>
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

  const agingFindings = [...data.findings]
    .filter(isFindingOpen)
    .sort((left, right) => String(left.created_at ?? left.id ?? '').localeCompare(String(right.created_at ?? right.id ?? '')))
    .slice(0, 8);

  const severityRows: { label: string; count: number; tone: 'danger' | 'warn' | 'muted' }[] = [
    { label: 'Critical (S1)', count: severity.critical, tone: 'danger' },
    { label: 'High (S2)', count: severity.high, tone: 'warn' },
    { label: 'Medium / Low', count: severity.other, tone: 'muted' }
  ];
  const severityMax = Math.max(1, severity.critical, severity.high, severity.other);

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
            <AnchorButton href="#runs" variant="default" size="sm">Run safe validation</AnchorButton>
          </>
        }
      />
      <PageContextSummary>
        <span className="tabular-nums">{targetsUnavailable ? '—' : formatNumber(declaredTargets)}</span>{' '}
        {`declared ${pluralize(declaredTargets, 'target')} · `}
        <span className="tabular-nums">{targetsUnavailable ? '—' : formatNumber(verifiedTargets)}</span>{' '}
        {`ownership verified · `}
        <span className="tabular-nums">{data.loadErrors.evidence ? '—' : formatNumber(data.evidence.length)}</span>{' '}
        {`evidence ${pluralize(data.evidence.length, 'record')} · high-scale remains SOC-gated`}
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
          <DefensePathStrip stages={defensePath} />

          <div className="dashboard-kpis" role="group" aria-label="Readiness key metrics">
            <div className="dashboard-kpi">
              <span className="dashboard-kpi-label">Readiness</span>
              <span className="dashboard-kpi-value">{score ?? '—'}{score !== null ? <span className="unit">/100</span> : null}</span>
              <span className="dashboard-kpi-sub">{executive.headline}</span>
            </div>
            <div className="dashboard-kpi">
              <span className="dashboard-kpi-label">Declared targets</span>
              <span className="dashboard-kpi-value">{targetsUnavailable ? '—' : formatNumber(declaredTargets)}</span>
              <span className="dashboard-kpi-sub">{targetsUnavailable ? 'Target data unavailable' : verifiedShare === null ? 'No targets declared yet' : `${formatNumber(verifiedTargets)} ownership verified (${verifiedShare}%)`}</span>
            </div>
            <div className="dashboard-kpi">
              <span className="dashboard-kpi-label">Evidence coverage</span>
              <span className="dashboard-kpi-value">{coveragePercent === null ? '—' : coveragePercent}{coveragePercent !== null ? <span className="unit">%</span> : null}</span>
              <span className="dashboard-kpi-sub">{coverageUnavailable ? 'Coverage unavailable' : `${formatNumber(targetsWithEvidence)} of ${formatNumber(declaredTargets)} targets have evidence-backed verdicts`}</span>
            </div>
            <div className="dashboard-kpi">
              <span className="dashboard-kpi-label">Open findings</span>
              <span className="dashboard-kpi-value">{data.loadErrors.findings ? '—' : formatNumber(severity.total)}</span>
              {data.loadErrors.findings ? (
                <span className="dashboard-kpi-sub">Finding data unavailable</span>
              ) : (
                <span className="dashboard-kpi-split">
                  <Badge tone="danger" title="Severity 1 (Critical)">{formatNumber(severity.critical)} critical</Badge>
                  <Badge tone="warn" title="Severity 2 (High)">{formatNumber(severity.high)} high</Badge>
                </span>
              )}
            </div>
          </div>

          <div className="an-dash-grid">
            <div className="dashboard-col">
              <Card>
                <CardHeader>
                  <div>
                    <CardTitle>Target posture</CardTitle>
                    <CardDescription>Declared targets, worst posture first. Open a row for its evidence and checks.</CardDescription>
                  </div>
                  <AnchorButton variant="ghost" size="sm" href="#targets">All targets</AnchorButton>
                </CardHeader>
                <CardContent>
                  <DataTable
                    columns={postureColumns}
                    items={postureRows}
                    loadError={[data.loadErrors.targets, data.loadErrors.runs].filter(Boolean).join(' ') || null}
                    onRetry={() => void onRefresh()}
                    getRowId={(row) => row.id}
                    getRowProps={(row) => rowProps('target-detail', row.id, `Open target ${row.value} detail`)}
                    empty={<EmptyState icon={Target} title="No targets declared yet." body="Declare a domain, hostname, IP, or CIDR to start validating readiness." actionHref="#targets" actionLabel="Declare a target" />}
                  />
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <div>
                    <CardTitle>Recent validation activity</CardTitle>
                    <CardDescription>The latest safe validation runs and their verdicts.</CardDescription>
                  </div>
                  <AnchorButton variant="ghost" size="sm" href="#runs">All runs</AnchorButton>
                </CardHeader>
                <CardContent>
                  <DataTable
                    columns={runColumns}
                    items={recentRuns}
                    loadError={data.loadErrors.runs}
                    onRetry={() => void onRefresh()}
                    getRowId={(item) => getString(item, ['id'])}
                    getRowProps={(item) => rowProps('run-detail', getString(item, ['id']), `Open run ${getString(item, ['id'])} detail`)}
                    empty={<EmptyState icon={ListChecks} title="No validation runs yet." body="Start a safe validation from Test Runs after declaring a target." actionHref="#runs" actionLabel="Open test runs" />}
                  />
                </CardContent>
              </Card>
            </div>

            <div className="dashboard-col">
              <Card>
                <CardHeader>
                  <div>
                    <CardTitle>What to fix first</CardTitle>
                    <CardDescription>Up to three actions backed by the evidence currently loaded.</CardDescription>
                  </div>
                  <Badge tone={nextSteps.length > 0 ? 'warn' : 'success'}>{formatNumber(nextSteps.length)} to review</Badge>
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
                          <AnchorButton href={step.href} variant="secondary" size="sm">Review</AnchorButton>
                        </li>
                      ))}
                    </ol>
                  ) : (
                    <EmptyState icon={ListChecks} title="No priority fix is loaded." body="Keep scheduled validation current so new gaps surface here." />
                  )}
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle>Readiness posture</CardTitle>
                  <CardDescription>Correlated checks this cycle</CardDescription>
                </CardHeader>
                <CardContent>
                  <ReadinessPostureDonut state={data.state} runs={data.runs} checks={data.checks} />
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle>Weighted factors</CardTitle>
                  <CardDescription>Each factor contributes its points to the published readiness score.</CardDescription>
                </CardHeader>
                <CardContent>
                  <WeightedFactors factors={readinessFactors} />
                </CardContent>
              </Card>
            </div>
          </div>

          <EvidenceGuide compact />
        </div>
      ) : null}

      {tab === 'risk-trends' ? (
        <div role="tabpanel" id="dashboard-sections-panel-risk-trends" aria-labelledby="dashboard-sections-tab-risk-trends" className="tab-panel">
          <div className="risk-trends">
            <Card className="risk-trends-hero">
              <CardHeader>
                <CardTitle>Readiness trend</CardTitle>
                <CardDescription>Published per-run scores, with evidence-backed verdict history when a numeric score is absent.</CardDescription>
              </CardHeader>
              <CardContent>
                {score === null ? (
                  <EmptyState icon={Activity} title="Readiness score unavailable." body="Trend appears after the platform publishes an evidence-backed score." />
                ) : (
                  <ScoreTrend runs={data.runs} currentScore={score} />
                )}
              </CardContent>
            </Card>

            <div className="risk-secondary">
              <Card>
                <CardHeader>
                  <CardTitle>Open findings by severity</CardTitle>
                  <CardDescription>Current open gaps grouped by severity.</CardDescription>
                </CardHeader>
                <CardContent>
                  {data.loadErrors.findings ? (
                    <EmptyState icon={TriangleAlert} title="Finding data unavailable." body="Severity distribution appears once findings load." />
                  ) : severity.total === 0 ? (
                    <EmptyState icon={TriangleAlert} title="No open findings." body="Open findings appear after validation runs produce evidence-backed gaps." />
                  ) : (
                    <div className="severity-dist" role="img" aria-label={`Open findings: ${severity.critical} critical, ${severity.high} high, ${severity.other} medium or low`}>
                      {severityRows.map((row) => (
                        <div className="severity-dist-row" key={row.label}>
                          <span className="severity-dist-label">{row.label}</span>
                          <span className="severity-dist-track" aria-hidden="true">
                            <span className="severity-dist-fill" data-tone={row.tone} style={{ width: `${Math.round((row.count / severityMax) * 100)}%` }} />
                          </span>
                          <span className="severity-dist-count">{formatNumber(row.count)}</span>
                        </div>
                      ))}
                    </div>
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
                        const id = getString(finding, ['id']);
                        return (
                          <li key={id}>
                            <div className="dashboard-link-copy">
                              <strong>{plainFindingTitle(finding, data.targets, data.checks)}</strong>
                              <span className="dashboard-link-meta">
                                <Badge tone={severityBadgeTone(getString(finding, ['severity']))}>{formatSeverityLabel(getString(finding, ['severity'], 'unknown'))}</Badge>
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
