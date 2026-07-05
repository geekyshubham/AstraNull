import { useEffect, useMemo, useState, type FormEvent, type ReactNode } from 'react';
import {
  Activity,
  Bot,
  CheckCircle2,
  ClipboardList,
  Clock3,
  FileCheck2,
  KeyRound,
  ListChecks,
  Network,
  RadioTower,
  ScanSearch,
  ShieldCheck,
  Siren,
  Target,
  TriangleAlert,
  ChevronDown
} from 'lucide-react';
import { Badge } from '../components/ui/badge';
import { AnchorButton, Button } from '../components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../components/ui/card';
import { EmptyState } from '../components/ui/empty-state';
import { Progress } from '../components/ui/progress';
import { Select } from '../components/ui/select';
import { DataTable, type TableColumn } from '../components/ui/table';
import { Tabs } from '../components/ui/tabs';
import { buildEvidenceCustodyManifest } from '../lib/custody';
import { buildEvidenceChainExport, summarizeEvidenceExport } from '../lib/evidence-export';
import {
  computeFindingKpis,
  filterFindingsByTab,
  findingSlaDueAt,
  findingsListSubtitle,
  groupedFindingsBadgeLabel,
  groupFindingsByTargetGroup,
  groupFindingsByVector,
  isFindingSlaBreach,
  type FindingTabId
} from '../lib/findings-helpers';
import {
  agentHeartbeatFreshness,
  agentInstallApiBase,
  filterAgentAuditEntries,
  formatAgentCapabilities,
  formatAgentHealth,
  formatAgentPlacement,
  formatHeartbeatFreshness,
  formatPlacementOverview,
  formatPlacementStatus,
  placementStatusHint,
  placementFactorScore
} from '../lib/agent-helpers';
import {
  CHECK_SAFETY_SCOPE_TABS,
  countChecksBySafetyScope,
  filterChecksCatalog,
  type CheckFamilyTabId,
  type CheckSafetyScopeId
} from '../lib/checks-helpers';
import { extractPlacementDiagnosticsFromReadiness } from '../lib/onboarding';
import { requestJson } from '../lib/api';

import { routeTabs } from '../lib/prototype-manifest';
import { buildDetailHref } from '../lib/route-params';
import type { DataItem, PortalConfig, PortalData, RouteId, Session } from '../lib/types';
import {
  DRIFT_EVENT_STATUSES,
  VALIDATION_PLAN_SCENARIOS,
  WAF_POSTURE_TABS,
  computeWafAssetPassRate,
  formatWafPassRateDisplay,
  formatWafRuleHealthDisplay,
  retestForDriftEvent,
  roadmapTierIds,
  roadmapTierMeta,
  roadmapTotalItems
} from '../lib/waf-helpers';
import { formatDate, scoreTone } from '../lib/utils';
import type { ProgressTone } from '../components/ui/progress';
import { MetricCard, PageHeader } from './page-components';

const WAF_POSTURE_SURFACE_TABS = [
  ...WAF_POSTURE_TABS,
  { id: 'operations', label: 'Operations' }
] as const;

type WafPostureSurfaceTabId = (typeof WAF_POSTURE_SURFACE_TABS)[number]['id'];

function getString(item: DataItem | null | undefined, keys: string[], fallback = '—') {
  if (!item) return fallback;
  for (const key of keys) {
    const value = item[key];
    if (value !== undefined && value !== null && value !== '') return String(value);
  }
  return fallback;
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

const VECTOR_FAMILY_ORDER = [
  'origin',
  'path',
  'l3_l4',
  'dns',
  'l7',
  'waf',
  'tls',
  'protocol',
  'operations',
  'high_scale'
] as const;

const VECTOR_FAMILY_LABELS: Record<string, string> = {
  origin: 'Origin',
  path: 'Path',
  l3_l4: 'L3/L4',
  dns: 'DNS',
  l7: 'L7/API',
  waf: 'WAF',
  tls: 'TLS',
  protocol: 'Protocol',
  operations: 'Operations',
  high_scale: 'High-scale'
};

function formatVectorFamilyLabel(family: string) {
  return VECTOR_FAMILY_LABELS[family] ?? family.replace(/_/g, ' ');
}

function formatSafetyClassLabel(safetyClass: string) {
  if (safetyClass === 'safe') return 'Customer-runnable';
  if (safetyClass === 'soc_gated') return 'SOC request-only';
  return safetyClass.replace(/_/g, ' ');
}

function formatRunStatusLabel(status: string) {
  const labels: Record<string, string> = {
    planned: 'Planned',
    running: 'Running',
    collecting: 'Collecting',
    verdicted: 'Verdicted',
    cancelled: 'Cancelled',
    failed: 'Failed'
  };
  return labels[status] ?? status.replace(/_/g, ' ');
}

function runStatusBadgeTone(status: string): 'default' | 'success' | 'warn' | 'danger' | 'info' | 'muted' {
  if (status === 'verdicted') return 'success';
  if (status === 'running' || status === 'collecting') return 'info';
  if (status === 'cancelled' || status === 'failed') return 'danger';
  if (status === 'planned') return 'muted';
  return 'warn';
}

type BadgeTone = 'default' | 'success' | 'warn' | 'danger' | 'info' | 'muted';

function verdictBadgeTone(verdict: string): BadgeTone {
  const normalized = verdict.toLowerCase();
  if (normalized === 'pass' || normalized === 'ready') return 'success';
  if (normalized === 'fail' || normalized === 'failed') return 'danger';
  if (normalized === 'partial' || normalized === 'inconclusive') return 'warn';
  if (normalized === 'pending' || normalized === '—' || !normalized) return 'muted';
  return 'info';
}

function formatVerdictLabel(verdict: string) {
  const normalized = verdict.toLowerCase();
  const labels: Record<string, string> = {
    pass: 'Pass',
    fail: 'Fail',
    partial: 'Partial',
    pending: 'Pending',
    inconclusive: 'Inconclusive',
    ready: 'Ready',
    failed: 'Failed'
  };
  return labels[normalized] ?? verdict.replace(/_/g, ' ');
}

function findingStatusBadgeTone(status: string): BadgeTone {
  const normalized = status.toLowerCase();
  if (normalized === 'open') return 'warn';
  if (normalized === 'closed' || normalized === 'resolved') return 'success';
  if (normalized === 'accepted_risk') return 'info';
  return 'muted';
}

function formatFindingStatusLabel(status: string) {
  const labels: Record<string, string> = {
    open: 'Open',
    closed: 'Closed',
    accepted_risk: 'Accepted risk',
    resolved: 'Resolved'
  };
  return labels[status.toLowerCase()] ?? status.replace(/_/g, ' ');
}

function wafAssetStatusBadgeTone(status: string): BadgeTone {
  const normalized = status.toLowerCase();
  if (normalized === 'protected') return 'success';
  if (normalized === 'underprotected' || normalized === 'unprotected') return 'danger';
  if (normalized === 'unknown') return 'warn';
  if (normalized === 'excluded') return 'muted';
  return 'warn';
}

function coverageProgressTone(status: string, percent: number): ProgressTone {
  if (status === 'protected') {
    if (percent >= 80) return 'success';
    if (percent >= 50) return 'warn';
    return 'danger';
  }
  if (status === 'excluded') return 'accent';
  if (percent > 0) return 'warn';
  return 'accent';
}

function cveStageBadgeTone(stage: string): BadgeTone {
  const normalized = stage.toLowerCase();
  if (normalized === 'resolved' || normalized === 'closed') return 'success';
  if (normalized === 'triaged' || normalized === 'validated') return 'info';
  if (normalized === 'blocked' || normalized === 'exploited') return 'danger';
  return 'warn';
}

function supplyChainStateBadgeTone(state: string): BadgeTone {
  const normalized = state.toLowerCase();
  if (normalized === 'confirmed') return 'danger';
  if (normalized === 'remediated' || normalized === 'resolved') return 'success';
  if (normalized === 'suspected' || normalized === 'open') return 'warn';
  if (normalized === 'dismissed') return 'muted';
  return 'info';
}

function placementStatusBadgeTone(status: string): BadgeTone {
  if (status === 'proven') return 'success';
  if (status === 'needs_baseline') return 'warn';
  if (status === 'missing_agent' || status === 'misplaced_risk') return 'danger';
  return 'muted';
}

function runDisplayLabelForId(checks: DataItem[], runs: DataItem[], runId: string) {
  if (!runId) return '—';
  const run = runs.find((entry) => getString(entry, ['id']) === runId);
  if (!run) return runId;
  const titled = getString(run, ['name', 'title'], '');
  if (titled) return titled;
  return checkDisplayName(checks, getString(run, ['check_id']));
}

function TableSkeleton({ rows = 4, label = 'Loading' }: { rows?: number; label?: string }) {
  return (
    <div className="stack-tight" aria-busy="true" aria-label={label}>
      {Array.from({ length: rows }, (_, index) => (
        <div key={index} className="skeleton skeleton-row" />
      ))}
    </div>
  );
}

function formatCoverageStatusLabel(status: string) {
  const labels: Record<string, string> = {
    protected: 'Protected',
    underprotected: 'Underprotected',
    unprotected: 'Unprotected',
    unknown: 'Unknown',
    excluded: 'Excluded'
  };
  return labels[status] ?? status.replace(/_/g, ' ');
}

function coverageBucketBadgeTone(status: string, count: number, percent: number): BadgeTone {
  if (status === 'protected') return scoreTone(percent);
  if (status === 'underprotected') return count > 0 ? 'warn' : 'muted';
  if (status === 'unprotected') return count > 0 ? 'danger' : 'muted';
  if (status === 'unknown') return count > 0 ? 'muted' : 'muted';
  if (status === 'excluded') return 'muted';
  return count > 0 ? 'warn' : 'muted';
}

function discoveryEntityStateBadgeTone(state: string): BadgeTone {
  const normalized = state.toLowerCase();
  if (normalized === 'approved' || normalized === 'active' || normalized === 'entity') return 'success';
  if (normalized === 'rejected') return 'danger';
  return 'warn';
}

function scrollElementIntoView(element: HTMLElement | null, block: ScrollLogicalPosition = 'start') {
  if (!element) return;
  const reduced = typeof window !== 'undefined' && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  element.scrollIntoView({ behavior: reduced ? 'auto' : 'smooth', block });
}

function coverageStatusHint(status: string) {
  const hints: Record<string, string> = {
    protected: 'Asset meets declared WAF protection expectations.',
    underprotected: 'Partial coverage or weak rule effectiveness.',
    unprotected: 'No effective WAF coverage on declared scope.',
    unknown: 'Insufficient evidence to classify coverage.',
    excluded: 'Out of scope for WAF posture scoring.'
  };
  return hints[status] ?? '';
}

function checkDisplayName(checks: DataItem[], checkId: string) {
  const check = checks.find((entry) => getString(entry, ['check_id']) === checkId);
  return getString(check ?? {}, ['name'], checkId);
}

function truncateText(text: string, max = 72) {
  if (text.length <= max) return text;
  return `${text.slice(0, max).trimEnd()}…`;
}

function formatSnakeLabel(value: string, fallback = '—') {
  const trimmed = value.trim();
  if (!trimmed) return fallback;
  return trimmed
    .split('_')
    .filter(Boolean)
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1).toLowerCase())
    .join(' ');
}

function formatSeverityLabel(severity: string) {
  return formatSnakeLabel(severity, '—');
}

const VALIDATION_SCENARIO_LABELS: Record<string, string> = {
  marker: 'WAF marker probe',
  fingerprint: 'Fingerprint validation',
  origin_bypass: 'Origin bypass check'
};

const REMEDIATION_STATUS_LABELS: Record<string, string> = {
  open: 'Open',
  ticketed: 'Ticketed',
  remediation_started: 'Remediation started',
  retest_pending: 'Retest pending',
  resolved: 'Resolved',
  accepted_risk: 'Accepted risk'
};

function formatRemediationStatusLabel(status: string) {
  return REMEDIATION_STATUS_LABELS[status] ?? formatSnakeLabel(status);
}

function formatSupplyChainStateLabel(state: string) {
  const labels: Record<string, string> = {
    suspected: 'Suspected',
    confirmed: 'Confirmed',
    remediated: 'Remediated',
    resolved: 'Resolved',
    dismissed: 'Dismissed',
    open: 'Open'
  };
  return labels[state.toLowerCase()] ?? formatSnakeLabel(state);
}

function formatDiscoveryStateLabel(state: string) {
  const labels: Record<string, string> = {
    entity: 'Entity',
    approved: 'Approved',
    approved_target: 'Approved target',
    rejected: 'Rejected',
    pending: 'Pending review',
    candidate: 'Candidate'
  };
  return labels[state.toLowerCase()] ?? formatSnakeLabel(state);
}

const DISCOVERY_REJECT_REASONS = [
  { id: 'not_in_scope', label: 'Not in scope' },
  { id: 'duplicate', label: 'Duplicate' },
  { id: 'low_confidence', label: 'Low confidence' }
] as const;

const REMEDIATION_CHANNEL_LABELS: Record<string, string> = {
  webhook: 'Webhook connector',
  jira: 'Jira',
  servicenow: 'ServiceNow',
  slack: 'Slack',
  siem: 'SIEM export'
};

const SUPPLY_CHAIN_EXPOSURE_TYPES = [
  { id: 'dangling_cname', label: 'Dangling CNAME', hint: 'DNS CNAME points to an unclaimed or expired destination.' },
  { id: 'subdomain_takeover', label: 'Subdomain takeover risk', hint: 'Host may be claimable via a third-party service.' },
  { id: 'orphan_record', label: 'Orphan DNS record', hint: 'Record exists without a matching declared asset.' },
  { id: 'customer_declared', label: 'Customer-declared exposure', hint: 'Manually declared supply-chain concern.' }
] as const;

const AGENT_SURFACE_TABS = [
  { id: 'fleet', label: 'Fleet' },
  { id: 'install', label: 'Install' },
  { id: 'operations', label: 'Operations' }
] as const;

function sortVectorFamilies(families: string[]) {
  return [...families].sort((a, b) => {
    const left = VECTOR_FAMILY_ORDER.indexOf(a as (typeof VECTOR_FAMILY_ORDER)[number]);
    const right = VECTOR_FAMILY_ORDER.indexOf(b as (typeof VECTOR_FAMILY_ORDER)[number]);
    if (left === -1 && right === -1) return a.localeCompare(b);
    if (left === -1) return 1;
    if (right === -1) return -1;
    return left - right;
  });
}

function getNumber(item: DataItem, keys: string[], fallback = 0) {
  for (const key of keys) {
    const value = item[key];
    if (typeof value === 'number' && Number.isFinite(value)) return value;
  }
  return fallback;
}

function getNestedItem(item: DataItem | null | undefined, path: string[]) {
  let current: unknown = item;
  for (const key of path) {
    if (!current || typeof current !== 'object' || Array.isArray(current)) return null;
    current = (current as DataItem)[key];
  }
  return current && typeof current === 'object' && !Array.isArray(current) ? current as DataItem : null;
}

function getNestedNumber(item: DataItem | null | undefined, path: string[], fallback = 0) {
  let current: unknown = item;
  for (const key of path) {
    if (!current || typeof current !== 'object' || Array.isArray(current)) return fallback;
    current = (current as DataItem)[key];
  }
  return typeof current === 'number' && Number.isFinite(current) ? current : fallback;
}

function featureEnabled(data: PortalData, key: 'waf_posture' | 'external_discovery') {
  const features = data.deploymentFeatures as { waf_posture?: boolean; external_discovery?: boolean } | null;
  return features?.[key] === true;
}

const ACTION_ITEM_STATUSES = ['open', 'ticketed', 'remediation_started', 'retest_pending', 'resolved', 'accepted_risk'] as const;
const CLOSED_ACTION_ITEM_STATUSES = new Set(['resolved', 'accepted_risk']);
const REMEDIATION_CHANNELS = ['webhook', 'jira', 'servicenow', 'slack', 'siem'] as const;

async function runAction<T>(
  setBusy: (v: string) => void,
  setError: (v: string) => void,
  setMessage: (v: string) => void,
  label: string,
  action: () => Promise<T>,
  success: string,
  onRefresh?: () => Promise<void>
) {
  setBusy(label);
  setError('');
  setMessage('');
  try {
    const result = await action();
    setMessage(success);
    if (onRefresh) await onRefresh();
    return result;
  } catch (err) {
    const payload = (err as Error & { payload?: unknown }).payload as { error?: string; message?: string } | undefined;
    setError(payload?.message ?? payload?.error ?? (err instanceof Error ? err.message : 'Action failed.'));
    return null;
  } finally {
    setBusy('');
  }
}

export function AgentsPage({
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
  const [tokenSecret, setTokenSecret] = useState('');
  const [agentTab, setAgentTab] = useState('fleet');
  const [installPlatform, setInstallPlatform] = useState('linux');
  const [placementReviews, setPlacementReviews] = useState<DataItem | null>(null);
  const [updateReleases, setUpdateReleases] = useState<DataItem[]>([]);
  const [trustKeys, setTrustKeys] = useState<DataItem[]>([]);
  const [auxLoading, setAuxLoading] = useState(false);
  const onlineAgents = data.agents.filter((agent) => getString(agent, ['status']) === 'online').length;
  const firstGroup = data.targetGroups[0] ?? null;
  const agentTabOptions = AGENT_SURFACE_TABS.map((tab) => ({ id: tab.id, label: tab.label }));
  const placementScore = placementFactorScore(data.state as DataItem | null);
  const placementSummary = getNestedItem(placementReviews, ['summary']);
  const readinessPlacement = extractPlacementDiagnosticsFromReadiness(data.state?.readiness as DataItem | undefined);
  const placementReviewRows = Array.isArray(placementReviews?.reviews) ? placementReviews.reviews as DataItem[] : [];
  const agentAuditEntries = filterAgentAuditEntries(data.audit);
  const placementReviewColumns: TableColumn<DataItem>[] = [
    {
      key: 'group',
      label: 'Target group',
      render: (review) => getString(review, ['target_group_name', 'target_group_id'], 'group')
    },
    {
      key: 'status',
      label: 'Placement status',
      render: (review) => {
        const status = getString(review, ['status'], 'unknown');
        const hint = placementStatusHint(status);
        return <Badge tone={placementStatusBadgeTone(status)} title={hint || undefined}>{formatPlacementStatus(status)}</Badge>;
      }
    },
    {
      key: 'summary',
      label: 'Summary',
      render: (review) => getString(review, ['summary'], '—')
    }
  ];

  const fleetColumns: TableColumn<DataItem>[] = [
    {
      key: 'id',
      label: 'ID',
      render: (item) => (
        <code className="traffic-path-label" title={getString(item, ['id'])}>{getString(item, ['id'])}</code>
      )
    },
    {
      key: 'health',
      label: 'Health',
      render: (item) => {
        const health = formatAgentHealth(item);
        const tone = health === 'online' ? 'success' : health === 'revoked' ? 'danger' : 'muted';
        return <Badge tone={tone}>{health}</Badge>;
      }
    },
    { key: 'version', label: 'Version', render: (item) => getString(item, ['version', 'agent_version'], '—') },
    { key: 'placement', label: 'Placement', render: (item) => formatAgentPlacement(item) },
    { key: 'last_heartbeat', label: 'Last heartbeat', render: (item) => formatDate(item.last_heartbeat_at) },
    {
      key: 'actions',
      label: 'Actions',
      render: (item) => {
        const id = getString(item, ['id'], '');
        const revoked = getString(item, ['status']) === 'revoked';
        return (
          <div className="row-actions">
            <AnchorButton size="sm" variant="secondary" href={buildDetailHref('agent-detail', id)}>Detail</AnchorButton>
            {!revoked ? <Button size="sm" variant="danger" loading={busy === `revoke-${id}`} disabled={busy !== ''} aria-label={`Revoke agent ${getString(item, ['hostname', 'name', 'id'], id)}`} onClick={() => void revokeAgent(id)}>Revoke</Button> : null}
          </div>
        );
      }
    }
  ];

  const healthColumns: TableColumn<DataItem>[] = [
    { key: 'name', label: 'Agent', render: (item) => getString(item, ['hostname', 'name', 'id']) },
    { key: 'status', label: 'Status', render: (item) => <Badge tone={getString(item, ['status']) === 'online' ? 'success' : 'muted'}>{formatAgentHealth(item)}</Badge> },
    { key: 'freshness', label: 'Heartbeat', render: (item) => formatHeartbeatFreshness(agentHeartbeatFreshness(item)) },
    { key: 'heartbeat', label: 'Last heartbeat', render: (item) => formatDate(item.last_heartbeat_at) },
    { key: 'version', label: 'Version', render: (item) => getString(item, ['version'], '—') },
    { key: 'fingerprint', label: 'Gateway fingerprint', render: (item) => <code>{getString(item, ['fingerprint'], 'not registered')}</code> }
  ];

  const capabilityColumns: TableColumn<DataItem>[] = [
    { key: 'name', label: 'Agent', render: (item) => getString(item, ['hostname', 'name', 'id']) },
    { key: 'capabilities', label: 'Observation modes', render: (item) => formatAgentCapabilities(item) },
    { key: 'environment', label: 'Environment', render: (item) => getString(item, ['environment_id'], 'tenant scope') },
    { key: 'group', label: 'Target group', render: (item) => getString(item, ['target_group_id'], 'unbound') }
  ];

  const releaseColumns: TableColumn<DataItem>[] = [
    { key: 'version', label: 'Version', render: (item) => getString(item, ['version']) },
    { key: 'channel', label: 'Channel', render: (item) => getString(item, ['channel'], 'stable') },
    { key: 'state', label: 'State', render: (item) => <Badge tone="info">{getString(item, ['state'], 'active')}</Badge> },
    { key: 'rollout', label: 'Rollout', render: (item) => `${getNestedNumber(item, ['rollout', 'percentage'], 100)}%` },
    { key: 'created', label: 'Created', render: (item) => formatDate(item.created_at) },
    {
      key: 'actions',
      label: 'Actions',
      render: (item) => {
        const id = getString(item, ['id'], '');
        const canRollback = Boolean(item.rollback) && getString(item, ['state']) !== 'rollback_requested';
        return canRollback ? (
          <Button size="sm" variant="secondary" loading={busy === `rollback-${id}`} disabled={busy !== ''} aria-label={`Request rollback for release ${getString(item, ['version'], id)}`} onClick={() => void requestReleaseRollback(id)}>Request rollback</Button>
        ) : <span className="muted">—</span>;
      }
    }
  ];

  const trustKeyColumns: TableColumn<DataItem>[] = [
    { key: 'name', label: 'Name', render: (item) => getString(item, ['name']) },
    { key: 'fingerprint', label: 'Fingerprint', render: (item) => <code>{getString(item, ['fingerprint_sha256'])}</code> },
    {
      key: 'status',
      label: 'Status',
      render: (item) => {
        const status = getString(item, ['status']);
        return <Badge tone={status === 'active' ? 'success' : 'muted'}>{formatSnakeLabel(status)}</Badge>;
      }
    },
    { key: 'created', label: 'Created', render: (item) => formatDate(item.created_at) },
    {
      key: 'actions',
      label: 'Actions',
      render: (item) => {
        const id = getString(item, ['id'], '');
        const active = getString(item, ['status']) === 'active';
        return active ? (
          <Button size="sm" variant="danger" loading={busy === `trust-revoke-${id}`} disabled={busy !== ''} aria-label={`Revoke trust key ${getString(item, ['name'], id)}`} onClick={() => void revokeTrustKey(id)}>Revoke</Button>
        ) : <span className="muted">revoked</span>;
      }
    }
  ];

  const logColumns: TableColumn<DataItem>[] = [
    { key: 'action', label: 'Action', render: (item) => getString(item, ['action']) },
    { key: 'resource', label: 'Resource', render: (item) => `${getString(item, ['resource_type'])}:${getString(item, ['resource_id'])}` },
    { key: 'actor', label: 'Actor', render: (item) => getString(item, ['actor_role'], 'system') },
    { key: 'when', label: 'Recorded', render: (item) => formatDate(item.created_at ?? item.timestamp) }
  ];

  useEffect(() => {
    if (!['operations', 'install', 'fleet'].includes(agentTab)) return undefined;
    let cancelled = false;
    setAuxLoading(true);
    requestJson(config, session, '/v1/placement/reviews')
      .then((payload) => {
        if (!cancelled) setPlacementReviews(payload as DataItem);
      })
      .catch(() => {
        if (!cancelled) setPlacementReviews(null);
      })
      .finally(() => {
        if (!cancelled) setAuxLoading(false);
      });
    return () => { cancelled = true; };
  }, [agentTab, config, session]);

  useEffect(() => {
    if (agentTab !== 'operations') return undefined;
    let cancelled = false;
    setAuxLoading(true);
    Promise.all([
      requestJson(config, session, '/v1/agent-updates'),
      requestJson(config, session, '/v1/agent-update-trust-keys')
    ])
      .then(([releasesPayload, trustPayload]) => {
        if (cancelled) return;
        const releases = Array.isArray((releasesPayload as { items?: unknown }).items)
          ? (releasesPayload as { items: DataItem[] }).items
          : [];
        const keys = Array.isArray((trustPayload as { items?: unknown }).items)
          ? (trustPayload as { items: DataItem[] }).items
          : [];
        setUpdateReleases(releases);
        setTrustKeys(keys);
      })
      .catch(() => {
        if (!cancelled) {
          setUpdateReleases([]);
          setTrustKeys([]);
        }
      })
      .finally(() => {
        if (!cancelled) setAuxLoading(false);
      });
    return () => { cancelled = true; };
  }, [agentTab, config, session]);

  async function createBootstrapToken() {
    const body: DataItem = {
      name: 'agent-install',
      expires_in_minutes: 60,
      max_registrations: 1
    };
    const environmentId = getString(firstGroup, ['environment_id'], '');
    const targetGroupId = getString(firstGroup, ['id'], '');
    if (environmentId) body.environment_id = environmentId;
    if (targetGroupId) body.target_group_id = targetGroupId;
    const created = await runAction(setBusy, setError, setMessage, 'create-bootstrap-token', () => requestJson(config, session, '/v1/bootstrap-tokens', {
      method: 'POST',
      body
    }), 'Bootstrap token created. Copy the one-time secret now.', onRefresh);
    const secret = getString(created as DataItem, ['secret'], getNestedString(created as DataItem, ['token', 'secret'], ''));
    if (secret) setTokenSecret(secret);
  }

  async function revokeAgent(id: string) {
    if (!id) return;
    if (!window.confirm('Revoke this agent\'s credentials? It will stop reporting until re-registered.')) return;
    await runAction(setBusy, setError, setMessage, `revoke-${id}`, () => requestJson(config, session, `/v1/agents/${id}/revoke`, { method: 'POST' }), 'Agent revoked. Heartbeat and jobs will be rejected.', onRefresh);
  }

  async function requestReleaseRollback(releaseId: string) {
    if (!releaseId) return;
    if (!window.confirm('Request rollback for this agent release? Eligible agents will move to the previous signed version.')) return;
    await runAction(setBusy, setError, setMessage, `rollback-${releaseId}`, () => requestJson(config, session, `/v1/agent-updates/${releaseId}/rollback`, { method: 'POST' }), 'Rollback requested for eligible agents.', async () => {
      const payload = await requestJson(config, session, '/v1/agent-updates') as { items?: DataItem[] };
      setUpdateReleases(Array.isArray(payload.items) ? payload.items : []);
      await onRefresh();
    });
  }

  async function revokeTrustKey(keyId: string) {
    if (!keyId) return;
    if (!window.confirm('Revoke this agent update trust key? Agents will reject updates signed with it.')) return;
    await runAction(setBusy, setError, setMessage, `trust-revoke-${keyId}`, () => requestJson(config, session, `/v1/agent-update-trust-keys/${keyId}/revoke`, { method: 'POST' }), 'Trust key revoked.', async () => {
      const payload = await requestJson(config, session, '/v1/agent-update-trust-keys') as { items?: DataItem[] };
      setTrustKeys(Array.isArray(payload.items) ? payload.items : []);
      await onRefresh();
    });
  }

  async function handleAddTrustKey(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    await runAction(setBusy, setError, setMessage, 'add-trust-key', () => requestJson(config, session, '/v1/agent-update-trust-keys', {
      method: 'POST',
      body: {
        name: String(form.get('name') ?? '').trim() || 'agent update signing key',
        public_key_der_base64: String(form.get('public_key_der_base64') ?? '').trim()
      }
    }), 'Trust key registered.', async () => {
      const payload = await requestJson(config, session, '/v1/agent-update-trust-keys') as { items?: DataItem[] };
      setTrustKeys(Array.isArray(payload.items) ? payload.items : []);
      event.currentTarget.reset();
      await onRefresh();
    });
  }

  const installToken = tokenSecret || '<BOOTSTRAP_TOKEN>';
  const apiBase = agentInstallApiBase();

  return (
    <div className="content">
      <PageHeader route="agents" />
      <div className="metric-grid three">
        <MetricCard label="Declared groups" value={data.targetGroups.length} sub="Manual or API import only" icon={Target} tone="info" />
        <MetricCard label="Agents" value={data.agents.length} sub="Outbound-only control channel" icon={Bot} tone="success" />
        <MetricCard label="Online agents" value={onlineAgents} sub="Current heartbeat status" icon={RadioTower} tone={onlineAgents > 0 ? 'success' : 'muted'} />
      </div>
      {(message || error) && <div className={error ? 'form-banner error' : 'form-banner'}>{error || message}</div>}
      <Tabs value={agentTab} options={agentTabOptions} onChange={setAgentTab} className="tabs-wrap" />
      {agentTab === 'install' ? (
        <div className="split">
          <Card>
            <CardHeader>
              <CardTitle>Install outbound agent</CardTitle>
              <CardDescription>Create a bootstrap token, then run the install command on your host. No inbound management port is required.</CardDescription>
            </CardHeader>
            <CardContent className="product-form">
              <div className="row-actions page-toolbar">
                <Button loading={busy === 'create-bootstrap-token'} disabled={busy !== ''} onClick={() => void createBootstrapToken()}>Create bootstrap token</Button>
              </div>
              <Tabs
                value={installPlatform}
                options={[
                  { id: 'linux', label: 'Linux' },
                  { id: 'docker', label: 'Docker' },
                  { id: 'helm', label: 'Helm' }
                ]}
                onChange={setInstallPlatform}
                className="tabs-wrap"
              />
              {installPlatform === 'linux' ? (
                <pre className="codeblock">{`curl -fsSL ${apiBase}/agents/install.sh \\
  | sudo ASTRANULL_API_URL="${apiBase}" \\
       ASTRANULL_BOOTSTRAP_TOKEN="${installToken}" bash`}</pre>
              ) : null}
              {installPlatform === 'docker' ? (
                <pre className="codeblock">{`docker run -d --name astranull-agent \\
  -e ASTRANULL_API_URL="${apiBase}" \\
  -e ASTRANULL_BOOTSTRAP_TOKEN="${installToken}" \\
  astranull/agent:latest`}</pre>
              ) : null}
              {installPlatform === 'helm' ? (
                <pre className="codeblock">{`helm upgrade --install astranull-agent ./charts/agent \\
  --namespace astranull --create-namespace \\
  --set apiUrl="${apiBase}" \\
  --set bootstrapToken="${installToken}"`}</pre>
              ) : null}
              {tokenSecret ? <p className="muted">One-time token shown. It will not be displayed again after refresh.</p> : null}
            </CardContent>
          </Card>
          <Card>
            <CardHeader>
              <CardTitle>Placement diagnostics</CardTitle>
              <CardDescription>Placement confidence from readiness scoring and per-group placement reviews.</CardDescription>
            </CardHeader>
            <CardContent className="kv-list">
              <div><span>Placement factor</span><strong>{placementScore != null ? `${placementScore}%` : 'Awaiting evidence'}</strong></div>
              <div><span>Online agents</span><strong>{onlineAgents}</strong></div>
              <div><span>Ready groups</span><strong>{getNestedNumber(placementSummary, ['proven'], getNumber(readinessPlacement ?? {}, ['proven'], 0))}</strong></div>
              <div><span>Offline agents</span><strong>{getNestedNumber(placementSummary, ['misplaced_risk'], getNumber(readinessPlacement ?? {}, ['misplaced_risk'], 0))}</strong></div>
            </CardContent>
          </Card>
        </div>
      ) : null}
      {agentTab === 'fleet' ? (
        <Card>
          <CardHeader>
            <CardTitle>Agent fleet</CardTitle>
            <CardDescription>Registered outbound agents. Revoke invalidates credentials immediately.</CardDescription>
          </CardHeader>
          <CardContent aria-busy={auxLoading || undefined}>
            {auxLoading ? <TableSkeleton rows={3} label="Refreshing agent fleet" /> : null}
            {!auxLoading ? <DataTable
              columns={fleetColumns}
              items={data.agents}
              empty={(
                <EmptyState
                  icon={Bot}
                  title="No agents have registered yet."
                  body="Create a bootstrap token on the Install tab, then install an outbound-only agent."
                  actionLabel="Go to Install"
                  onAction={() => setAgentTab('install')}
                />
              )}
            /> : null}
          </CardContent>
        </Card>
      ) : null}
      {agentTab === 'operations' ? (
        <div className="stack">
          <Card>
            <CardHeader>
              <CardTitle>Agent health</CardTitle>
              <CardDescription>Heartbeat freshness and gateway trust metadata for each registered agent.</CardDescription>
            </CardHeader>
            <CardContent>
              {auxLoading ? <TableSkeleton rows={3} label="Loading agent health" /> : null}
              {!auxLoading ? <DataTable
                columns={healthColumns}
                items={data.agents}
                empty={<EmptyState icon={Activity} title="No agents to monitor." body="Register an agent to see heartbeat freshness and version posture." />}
              /> : null}
            </CardContent>
          </Card>
          <Card>
            <CardHeader>
              <CardTitle>Agent coverage by target group</CardTitle>
              <CardDescription>
                A target group is a set of URLs or hosts you want to test together. Each group needs its own agent on the traffic path.
              </CardDescription>
            </CardHeader>
            <CardContent>
              {auxLoading ? <TableSkeleton rows={3} label="Loading placement reviews" /> : null}
              {!auxLoading && placementReviewRows.length === 0 ? (
                <EmptyState icon={Target} title="No placement reviews yet." body="Declare target groups and register agents to compute placement confidence." />
              ) : null}
              {!auxLoading && placementReviewRows.length > 0 ? (
                <DataTable
                  columns={placementReviewColumns}
                  items={placementReviewRows}
                  empty={<EmptyState icon={Target} title="No placement reviews yet." body="Declare target groups and register agents to compute placement confidence." />}
                />
              ) : null}
              {placementSummary ? (
                <div className="stack-tight">
                  <p className="muted">{formatPlacementOverview(placementSummary)}</p>
                </div>
              ) : null}
            </CardContent>
          </Card>
          <Card>
            <CardHeader>
              <CardTitle>Agent capabilities</CardTitle>
              <CardDescription>Observation modes reported on registration and each heartbeat.</CardDescription>
            </CardHeader>
            <CardContent>
              <DataTable
                columns={capabilityColumns}
                items={data.agents}
                empty={<EmptyState icon={ListChecks} title="No capability reports yet." body="Capabilities appear after the first agent heartbeat." />}
              />
            </CardContent>
          </Card>
          <Card>
            <CardHeader>
              <CardTitle>Agent audit trail</CardTitle>
              <CardDescription>Metadata-only lifecycle events for agent registration, heartbeat, revoke, and updates—not host operational logs.</CardDescription>
            </CardHeader>
            <CardContent>
              <DataTable
                columns={logColumns}
                items={agentAuditEntries}
                empty={<EmptyState icon={ClipboardList} title="No agent audit events yet." body="Registration, heartbeat, revoke, and update actions appear here after agents connect." />}
              />
            </CardContent>
          </Card>
          <div className="split">
            <Card>
              <CardHeader>
                <CardTitle>Release rollout</CardTitle>
                <CardDescription>Tenant release rollouts. Agents pull signed updates over the outbound channel.</CardDescription>
              </CardHeader>
              <CardContent>
                {auxLoading ? <TableSkeleton rows={3} label="Loading agent releases" /> : null}
                {!auxLoading ? <DataTable
                  columns={releaseColumns}
                  items={updateReleases}
                  empty={<EmptyState icon={Bot} title="No agent releases published." body="Publish signed manifests through your operator packaging workflow to roll out agent versions." />}
                /> : null}
              </CardContent>
            </Card>
            <Card>
              <CardHeader>
                <CardTitle>Trust keys</CardTitle>
                <CardDescription>Ed25519 signing keys that agents trust for update manifests.</CardDescription>
              </CardHeader>
              <CardContent className="product-form">
                {auxLoading ? <TableSkeleton rows={2} label="Loading trust keys" /> : null}
                {!auxLoading ? <DataTable
                  columns={trustKeyColumns}
                  items={trustKeys}
                  empty={<EmptyState icon={KeyRound} title="No trust keys registered." body="Add the public key from your agent update signing ceremony." />}
                /> : null}
                <form className="product-form" onSubmit={(event) => void handleAddTrustKey(event)}>
                  <label><span>Key name</span><input name="name" placeholder="production signing key" /></label>
                  <label className="full"><span>Public key (DER base64)</span><textarea name="public_key_der_base64" rows={3} placeholder="MCowBQYDK2VwAyEA…" required /></label>
                  <div className="form-actions full"><Button type="submit" loading={busy === 'add-trust-key'} disabled={busy !== ''}>Register trust key</Button></div>
                </form>
              </CardContent>
            </Card>
          </div>
        </div>
      ) : null}
    </div>
  );
}

export function ValidationSurfacePage({
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
  const [checkFilter, setCheckFilter] = useState<CheckFamilyTabId>('recommended');
  const [checkSafetyScope, setCheckSafetyScope] = useState<CheckSafetyScopeId>('all');
  const [findingTab, setFindingTab] = useState<FindingTabId>('open');
  const [exportOutput, setExportOutput] = useState('');
  const [showTechnicalExport, setShowTechnicalExport] = useState(false);
  const [showFullEvidenceChain, setShowFullEvidenceChain] = useState(false);
  const [evidenceCustodyPreview, setEvidenceCustodyPreview] = useState<DataItem | null>(null);
  const [showEvidenceExportCenter, setShowEvidenceExportCenter] = useState(() => data.evidence.length > 0);
  const [exportPartialMissCount, setExportPartialMissCount] = useState(0);
  const [clipboardNotice, setClipboardNotice] = useState('');
  const [runStatusFilter, setRunStatusFilter] = useState('all');
  const [runStartTargetPreview, setRunStartTargetPreview] = useState('');
  const [runStartTargetLoading, setRunStartTargetLoading] = useState(false);
  const evidenceChainCap = 12;

  const firstGroup = data.targetGroups[0] ?? null;
  const safeCheck = data.checks.find((check) => getString(check, ['safety_class']) === 'safe') ?? null;
  const inFlightRuns = data.runs.filter((run) => ['running', 'collecting', 'planned'].includes(getString(run, ['status'], '')));

  const checkSafetyCounts = useMemo(() => countChecksBySafetyScope(data.checks), [data.checks]);
  const filteredChecks = useMemo(
    () => filterChecksCatalog(data.checks, checkFilter, checkSafetyScope),
    [data.checks, checkFilter, checkSafetyScope]
  );

  const filteredRuns = useMemo(() => {
    const sorted = [...data.runs].sort((a, b) => {
      const left = Date.parse(String(a.started_at ?? a.created_at ?? '')) || 0;
      const right = Date.parse(String(b.started_at ?? b.created_at ?? '')) || 0;
      return right - left;
    });
    if (runStatusFilter === 'all') return sorted;
    return sorted.filter((run) => getString(run, ['status'], '') === runStatusFilter);
  }, [data.runs, runStatusFilter]);

  useEffect(() => {
    if (route !== 'runs') return undefined;
    const targetGroupId = getString(firstGroup, ['id'], '');
    if (!targetGroupId) {
      setRunStartTargetPreview('');
      setRunStartTargetLoading(false);
      return undefined;
    }
    let cancelled = false;
    setRunStartTargetLoading(true);
    requestJson(config, session, `/v1/target-groups/${targetGroupId}`)
      .then((detail) => {
        if (cancelled) return;
        const targets = Array.isArray((detail as DataItem).targets) ? (detail as DataItem).targets as DataItem[] : [];
        const firstTarget = targets[0];
        const label = firstTarget
          ? `${getString(firstTarget, ['value', 'hostname', 'id'])} (${getString(firstTarget, ['id'])})`
          : '';
        setRunStartTargetPreview(label);
      })
      .catch(() => {
        if (!cancelled) setRunStartTargetPreview('');
      })
      .finally(() => {
        if (!cancelled) setRunStartTargetLoading(false);
      });
    return () => { cancelled = true; };
  }, [route, firstGroup, config, session]);

  useEffect(() => {
    if (data.evidence.length > 0) setShowEvidenceExportCenter(true);
  }, [data.evidence.length]);

  useEffect(() => {
    if (route !== 'runs' || inFlightRuns.length === 0) return undefined;
    const timer = window.setInterval(() => {
      void onRefresh();
    }, 12000);
    return () => window.clearInterval(timer);
  }, [route, inFlightRuns.length, onRefresh]);

  async function startSafeRun(checkId?: string) {
    const targetGroupId = getString(firstGroup, ['id'], '');
    const resolvedCheckId = checkId ?? getString(safeCheck ?? {}, ['check_id'], '');
    if (!targetGroupId || !resolvedCheckId) {
      setError('Declare a target group and safe check before starting a run.');
      return;
    }
    const detail = await requestJson(config, session, `/v1/target-groups/${targetGroupId}`) as DataItem;
    const targets = Array.isArray(detail.targets) ? detail.targets as DataItem[] : [];
    const targetId = getString(targets[0] ?? {}, ['id'], '');
    const targetLabel = getString(targets[0] ?? {}, ['value', 'hostname', 'id'], targetId);
    if (!targetId) {
      setError('Add at least one target to the declared group before starting a run.');
      return;
    }
    const groupLabel = getString(firstGroup, ['name', 'id'], targetGroupId);
    const checkLabel = checkDisplayName(data.checks, resolvedCheckId);
    if (!window.confirm(`Start a safe validation run?\n\nTarget group: ${groupLabel}\nTarget: ${targetLabel}\nCheck: ${checkLabel}`)) return;
    await runAction(setBusy, setError, setMessage, 'start-safe-run', () => requestJson(config, session, '/v1/test-runs', {
      method: 'POST',
      body: { target_group_id: targetGroupId, target_id: targetId, check_id: resolvedCheckId }
    }), 'Safe validation run started.', onRefresh);
  }

  async function cancelRun(id: string) {
    if (!id) return;
    if (!window.confirm('Cancel this run in progress?')) return;
    await runAction(setBusy, setError, setMessage, `cancel-${id}`, () => requestJson(config, session, `/v1/test-runs/${id}/cancel`, { method: 'POST' }), 'Run cancelled.', onRefresh);
  }

  async function finalizeRun(id: string) {
    if (!id) return;
    if (!window.confirm('Force finalize this run now? This locks the verdict.')) return;
    await runAction(setBusy, setError, setMessage, `finalize-${id}`, () => requestJson(config, session, `/v1/test-runs/${id}/finalize`, { method: 'POST' }), 'Run finalized after observation window.', onRefresh);
  }

  async function exportEvidenceChain() {
    if (!data.evidence.length) {
      setError('No evidence records available to export.');
      return;
    }
    const preview = buildEvidenceChainExport({
      evidence: data.evidence,
      runs: data.runs,
      findings: data.findings
    });
    const summary = summarizeEvidenceExport(preview).map(([label, value]) => `${label}: ${value}`).join('\n');
    if (!window.confirm(`Export evidence chain JSON?\n\nThis fetches up to 20 recent run details for verdict correlation.\n\n${summary}`)) return;
    setBusy('export-evidence-chain');
    setError('');
    setMessage('');
    setClipboardNotice('');
    setExportPartialMissCount(0);
    try {
      const verdicts: DataItem[] = [];
      let partialMisses = 0;
      for (const run of data.runs.slice(-20)) {
        const runId = getString(run, ['id'], '');
        if (!runId) continue;
        try {
          const detail = await requestJson(config, session, `/v1/test-runs/${runId}`) as DataItem;
          const verdict = detail.verdict as DataItem | undefined;
          if (verdict) verdicts.push({ ...verdict, test_run_id: runId });
        } catch {
          partialMisses += 1;
        }
      }
      setExportPartialMissCount(partialMisses);
      const exportData = buildEvidenceChainExport({
        evidence: data.evidence,
        runs: data.runs,
        verdicts,
        findings: data.findings
      });
      const custody = await buildEvidenceCustodyManifest(exportData.payload, session.tenant_id ?? 'ten_demo');
      const verified = await requestJson(config, session, '/v1/custody/verify', {
        method: 'POST',
        body: { payload: exportData.payload, custody }
      }) as DataItem;
      setExportOutput(exportData.json);
      setEvidenceCustodyPreview(getNestedItem(verified, ['verification']) ?? verified);
      setMessage(partialMisses > 0
        ? `Evidence chain exported with custody verified. ${partialMisses} run(s) missing verdict detail.`
        : 'Evidence chain exported and custody digest verified.');
      try {
        await navigator.clipboard.writeText(exportData.json);
        setClipboardNotice('Export JSON copied to clipboard.');
      } catch {
        setClipboardNotice('Could not copy to clipboard. Use Copy export JSON or download from preview.');
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Evidence chain export failed.');
      setEvidenceCustodyPreview(null);
    } finally {
      setBusy('');
    }
  }

  if (route === 'checks') {
    const checkTabOptions = routeTabs('checks').map((tab) => ({ id: tab.id as CheckFamilyTabId, label: tab.label }));
    const safetyScopeOptions = CHECK_SAFETY_SCOPE_TABS.map((tab) => ({
      id: tab.id,
      label: `${tab.label} (${checkSafetyCounts[tab.id]})`
    }));
    const columns: TableColumn<DataItem>[] = [
      {
        key: 'check',
        label: 'Check',
        render: (item) => {
          const checkId = getString(item, ['check_id'], '');
          const name = getString(item, ['name'], '');
          return (
            <div className="stack-tight">
              <strong>{name || checkId}</strong>
              {name ? <span className="muted small"><code>{checkId}</code></span> : null}
            </div>
          );
        }
      },
      {
        key: 'family',
        label: 'Family',
        render: (item) => <Badge tone="info">{formatVectorFamilyLabel(getString(item, ['vector_family']))}</Badge>
      },
      {
        key: 'safety',
        label: 'Safety',
        render: (item) => {
          const safetyClass = getString(item, ['safety_class'], '');
          return <Badge tone={safetyClass === 'safe' ? 'success' : 'warn'}>{formatSafetyClassLabel(safetyClass)}</Badge>;
        }
      },
      {
        key: 'description',
        label: 'Summary',
        render: (item) => {
          const description = getString(item, ['description'], '');
          if (!description || description === '—') return '—';
          return <span title={description}>{truncateText(description)}</span>;
        }
      },
      {
        key: 'probe',
        label: 'Probe profile',
        render: (item) => {
          const kind = getString(item, ['probe_profile', 'kind'], '');
          if (!kind || kind === '—') return <span className="muted">Unknown</span>;
          return formatSnakeLabel(kind);
        }
      },
      {
        key: 'actions',
        label: 'Actions',
        render: (item) => {
          const checkId = getString(item, ['check_id'], '');
          const isSafe = getString(item, ['safety_class']) === 'safe';
          return (
            <div className="row-actions row-actions--spaced">
              <AnchorButton variant="secondary" href="#test-policies">Bind in policy</AnchorButton>
              {isSafe ? (
                <Button variant="ghost" loading={busy === 'start-safe-run'} disabled={busy !== ''} onClick={() => void startSafeRun(checkId)}>Start safe run</Button>
              ) : null}
            </div>
          );
        }
      }
    ];
    return (
      <div className="content">
        <PageHeader route="checks" />
        <div className="metric-grid three">
          <MetricCard label="Catalog checks" value={checkSafetyCounts.all} sub="Tenant-visible definitions" icon={ListChecks} tone="info" />
          <MetricCard label="Runnable" value={checkSafetyCounts.safe} sub="Customer-safe scope" icon={ShieldCheck} tone="success" />
          <MetricCard label="SOC-only" value={checkSafetyCounts.soc} sub="Request through SOC" icon={Siren} tone="warn" />
        </div>
        <Card>
          <CardHeader>
            <CardTitle>Check library</CardTitle>
            <CardDescription>
              Browse the validation catalog by safety scope and vector family. High-scale checks remain request-only through SOC.
              {' '}
              <span className="muted small">
                {checkSafetyCounts.all} catalog · {checkSafetyCounts.safe} runnable · {checkSafetyCounts.soc} SOC-only
              </span>
            </CardDescription>
          </CardHeader>
          <CardContent>
            <fieldset className="filter-fieldset">
              <legend>Safety scope</legend>
              <Tabs value={checkSafetyScope} options={safetyScopeOptions} onChange={setCheckSafetyScope} className="tabs-wrap" />
            </fieldset>
            <fieldset className="filter-fieldset">
              <legend>Vector family</legend>
              <Tabs value={checkFilter} options={checkTabOptions} onChange={(value) => setCheckFilter(value as CheckFamilyTabId)} className="tabs-wrap" />
            </fieldset>
            <DataTable
              columns={columns}
              items={filteredChecks}
              empty={checkFilter === 'custom' ? (
                <EmptyState icon={ListChecks} title="No custom checks in catalog." body="Customer-defined safe checks bind through test policies after staff-reviewed scope declaration." actionLabel="Open test policies" actionHref="#test-policies" />
              ) : (
                <EmptyState icon={ListChecks} title="No checks in this family." body="The check catalog appears after your tenant is provisioned and scope is declared." />
              )}
            />
          </CardContent>
        </Card>
      </div>
    );
  }

  if (route === 'runs') {
    const runStatusTabs = [
      { id: 'all', label: 'All' },
      { id: 'running', label: 'Running' },
      { id: 'collecting', label: 'Collecting' },
      { id: 'verdicted', label: 'Verdicted' },
      { id: 'cancelled', label: 'Cancelled' },
      { id: 'failed', label: 'Failed' }
    ];
    const runColumns: TableColumn<DataItem>[] = [
      {
        key: 'run',
        label: 'Run',
        render: (item) => {
          const id = getString(item, ['id'], '');
          const checkId = getString(item, ['check_id'], '');
          return (
            <div className="stack-tight">
              <AnchorButton variant="secondary" href={buildDetailHref('run-detail', id)}>{checkDisplayName(data.checks, checkId)}</AnchorButton>
              <span className="muted small"><code>{id}</code></span>
            </div>
          );
        }
      },
      {
        key: 'status',
        label: 'Status',
        render: (item) => {
          const status = getString(item, ['status'], '');
          return <Badge tone={runStatusBadgeTone(status)}>{formatRunStatusLabel(status)}</Badge>;
        }
      },
      {
        key: 'verdict',
        label: 'Verdict',
        render: (item) => {
          const verdict = getString(item, ['verdict', 'verdict'], 'pending');
          return <Badge tone={verdictBadgeTone(verdict)}>{formatVerdictLabel(verdict)}</Badge>;
        }
      },
      { key: 'time', label: 'Started', render: (item) => formatDate(item.started_at ?? item.created_at) },
      {
        key: 'actions',
        label: 'Actions',
        render: (item) => {
          const id = getString(item, ['id'], '');
          const status = getString(item, ['status'], '');
          const cancellable = ['planned', 'running', 'collecting'].includes(status);
          return (
            <div className="row-actions row-actions--spaced">
              <AnchorButton variant="secondary" href={buildDetailHref('run-detail', id)}>View run</AnchorButton>
              {cancellable ? (
                <>
                  <Button size="sm" variant="danger" loading={busy === `cancel-${id}`} disabled={busy !== ''} onClick={() => void cancelRun(id)}>Cancel</Button>
                  <Button size="sm" variant="ghost" loading={busy === `finalize-${id}`} disabled={busy !== ''} onClick={() => void finalizeRun(id)}>Finalize</Button>
                </>
              ) : null}
            </div>
          );
        }
      }
    ];
    const canStartRun = Boolean(firstGroup && safeCheck && runStartTargetPreview);
    const startDisabledReason = !firstGroup
      ? 'Declare a target group first.'
      : !safeCheck
        ? 'No customer-runnable check in catalog.'
        : !runStartTargetPreview
          ? 'Add at least one target to the first target group.'
          : '';
    return (
      <div className="content">
        <PageHeader route="runs" />
        {inFlightRuns.length > 0 ? (
          <div className="form-banner info" role="status">Runs in progress — auto-refreshing every 12s ({inFlightRuns.length} active).</div>
        ) : null}
        {(message || error) && <div className={error ? 'form-banner error' : 'form-banner neutral'}>{error || message}</div>}
        <Card>
          <CardHeader>
            <CardTitle>Start safe validation</CardTitle>
            <CardDescription>Confirm the resolved target group, target, and check before starting a bounded safe run.</CardDescription>
          </CardHeader>
          <CardContent className="stack-tight">
            <div className="kv-list kv-list--compact">
              <div><span>Target group</span><strong>{firstGroup ? getString(firstGroup, ['name', 'id']) : '—'}</strong></div>
              <div>
                <span>Target</span>
                {runStartTargetLoading ? (
                  <span className="skeleton skeleton-text" aria-busy="true" aria-label="Loading target preview" />
                ) : (
                  <strong>{runStartTargetPreview || '—'}</strong>
                )}
              </div>
              <div>
                <span>Check</span>
                {safeCheck ? (
                  <div className="stack-tight">
                    <AnchorButton variant="ghost" href="#checks">{getString(safeCheck, ['name'], getString(safeCheck, ['check_id']))}</AnchorButton>
                    <span className="muted small"><code>{getString(safeCheck, ['check_id'])}</code></span>
                  </div>
                ) : (
                  <strong>—</strong>
                )}
              </div>
            </div>
            {startDisabledReason ? <p className="muted">{startDisabledReason}</p> : null}
            <Button loading={busy === 'start-safe-run'} disabled={busy !== '' || !canStartRun} onClick={() => void startSafeRun()}>Start safe run</Button>
          </CardContent>
        </Card>
        <Card>
          <CardHeader><CardTitle>Test runs</CardTitle><CardDescription>Live safe-validation runs with probe results, agent observations, and verdicts. Open a run for detail, or cancel or finalize in flight.</CardDescription></CardHeader>
          <CardContent>
            <Tabs value={runStatusFilter} options={runStatusTabs} onChange={setRunStatusFilter} className="tabs-wrap" />
            <DataTable columns={runColumns} items={filteredRuns} empty={<EmptyState icon={Activity} title="No test runs yet." body="Start a safe validation run after declaring target scope." actionLabel="Open onboarding" actionHref="#onboarding" />} />
          </CardContent>
        </Card>
      </div>
    );
  }

  if (route === 'findings') {
    const findingKpis = computeFindingKpis(data.findings);
    const findingTabOptions = routeTabs('findings').map((tab) => ({ id: tab.id as FindingTabId, label: tab.label }));
    const filteredFindings = filterFindingsByTab(data.findings, findingTab, data.checks);
    const groupedByTargetGroup = groupFindingsByTargetGroup(filteredFindings, data.targetGroups);
    const groupedByVector = groupFindingsByVector(filteredFindings, data.checks);

    const findingColumns: TableColumn<DataItem>[] = [
      {
        key: 'title',
        label: 'Finding',
        render: (item) => {
          const id = getString(item, ['id'], '');
          const title = getString(item, ['title', 'id'], id);
          return id ? (
            <AnchorButton size="sm" variant="ghost" href={buildDetailHref('finding-detail', id)} aria-label={`View finding ${title}`}>{title}</AnchorButton>
          ) : title;
        }
      },
      { key: 'severity', label: 'Severity', render: (item) => <Badge tone={['critical', 'high'].includes(getString(item, ['severity']).toLowerCase()) ? 'danger' : 'warn'}>{formatSeverityLabel(getString(item, ['severity']))}</Badge> },
      {
        key: 'status',
        label: 'Status',
        render: (item) => {
          const status = getString(item, ['status']);
          return <Badge tone={findingStatusBadgeTone(status)}>{formatFindingStatusLabel(status)}</Badge>;
        }
      },
      ...(findingTab === 'target-group' ? [{
        key: 'target-group',
        label: 'Target group',
        render: (item: DataItem) => {
          const groupId = getString(item, ['target_group_id'], '');
          if (!groupId) return '—';
          const group = data.targetGroups.find((entry) => getString(entry, ['id']) === groupId);
          const label = group ? getString(group, ['name', 'id'], groupId) : groupId;
          return <AnchorButton variant="ghost" href={buildDetailHref('target-group-detail', groupId)}>{label}</AnchorButton>;
        }
      }] as TableColumn<DataItem>[] : []),
      ...(findingTab === 'vector' ? [{
        key: 'vector',
        label: 'Vector',
        render: (item: DataItem) => formatVectorFamilyLabel(getString(item, ['vector_family'], getString(
          data.checks.find((check) => getString(check, ['check_id']) === getString(item, ['check_id'], '')) ?? {},
          ['vector_family'],
          'other'
        )))
      }] as TableColumn<DataItem>[] : []),
      ...(findingTab === 'sla' ? [{
        key: 'sla',
        label: 'SLA',
        render: (item: DataItem) => {
          const dueAt = findingSlaDueAt(item);
          if (!dueAt) return '—';
          return (
            <Badge tone={isFindingSlaBreach(item) ? 'danger' : 'warn'}>
              Due {formatDate(dueAt)}
            </Badge>
          );
        }
      }] as TableColumn<DataItem>[] : []),
      { key: 'time', label: 'Updated', render: (item) => formatDate(item.updated_at ?? item.created_at) },
      {
        key: 'actions',
        label: 'Actions',
        render: (item) => {
          const id = getString(item, ['id'], '');
          return (
            <AnchorButton variant="secondary" href={buildDetailHref('finding-detail', id)} aria-label={`View finding detail for ${getString(item, ['title', 'id'], id)}`}>View</AnchorButton>
          );
        }
      }
    ];

    const findingsEmpty = (
      <EmptyState
        icon={TriangleAlert}
        title={`No ${findingTabOptions.find((tab) => tab.id === findingTab)?.label.toLowerCase() ?? 'matching'} findings.`}
        body="Findings appear after failing verdicts are published and triaged."
        actionLabel="View test runs"
        actionHref="#runs"
      />
    );

    const renderFindingTable = (items: DataItem[]) => (
      <DataTable columns={findingColumns} items={items} empty={findingsEmpty} />
    );

    return (
      <div className="content">
        <PageHeader route="findings" />
        {(message || error) && <div className={error ? 'form-banner error' : 'form-banner neutral'}>{error || message}</div>}
        <div className="metric-grid four">
          <MetricCard label="Open" value={findingKpis.openCount} sub={findingKpis.openSeverityBreakdown} icon={TriangleAlert} tone="warn" />
          <MetricCard label="Accepted risk" value={findingKpis.acceptedRiskCount} sub="Acknowledged gaps" icon={ShieldCheck} tone="info" />
          <MetricCard label="Closed (30d)" value={findingKpis.closed30dCount} sub="Recently resolved" icon={CheckCircle2} tone="success" />
          <MetricCard label="SLA breach" value={findingKpis.slaBreachCount} sub="Needs attention" icon={Clock3} tone={findingKpis.slaBreachCount > 0 ? 'danger' : 'muted'} />
        </div>
        <Card>
          <CardHeader>
            <CardTitle>Findings</CardTitle>
            <CardDescription>
              Evidence-backed posture gaps with triage views and quick filters. Accept, close, custody export, and retest live on finding detail.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <Tabs value={findingTab} options={findingTabOptions} onChange={setFindingTab} className="tabs-wrap" />
            {findingsListSubtitle(findingTab) ? <p className="muted">{findingsListSubtitle(findingTab)}</p> : null}
            {findingTab === 'target-group' ? (
              groupedByTargetGroup.length === 0 ? findingsEmpty : (
                <div className="finding-group-sections">
                  {groupedByTargetGroup.map((group) => (
                    <section key={group.groupId} className="finding-group-section">
                      <div className="finding-group-header">
                        <h4>{group.label}</h4>
                        <Badge tone="info">{groupedFindingsBadgeLabel(findingTab, group.items.length)}</Badge>
                      </div>
                      {renderFindingTable(group.items)}
                    </section>
                  ))}
                </div>
              )
            ) : findingTab === 'vector' ? (
              groupedByVector.length === 0 ? findingsEmpty : (
                <div className="finding-group-sections">
                  {groupedByVector.map((group) => (
                    <section key={group.family} className="finding-group-section">
                      <div className="finding-group-header">
                        <h4>{group.label}</h4>
                        <Badge tone="info">{groupedFindingsBadgeLabel(findingTab, group.items.length)}</Badge>
                      </div>
                      {renderFindingTable(group.items)}
                    </section>
                  ))}
                </div>
              )
            ) : renderFindingTable(filteredFindings)}
          </CardContent>
        </Card>
      </div>
    );
  }

  // evidence
  const evidenceColumns: TableColumn<DataItem>[] = [
    {
      key: 'evidence',
      label: 'Evidence',
      render: (item) => {
        const id = getString(item, ['id'], '');
        const kind = getString(item, ['label', 'kind', 'signal_type'], 'record');
        return (
          <div className="stack-tight">
            <strong>{kind}</strong>
            <span className="muted small"><code>{id}</code></span>
          </div>
        );
      }
    },
    { key: 'run', label: 'Test run', render: (item) => {
      const runId = getString(item, ['test_run_id'], '');
      return runId ? (
        <AnchorButton variant="ghost" href={buildDetailHref('run-detail', runId)}>{runDisplayLabelForId(data.checks, data.runs, runId)}</AnchorButton>
      ) : '—';
    } },
    {
      key: 'source',
      label: 'Source',
      render: (item) => getString(item, ['source'], getNestedString(item, ['metadata', 'simulation'], getNestedString(item, ['metadata', 'vector_family'], '—')))
    },
    { key: 'time', label: 'Recorded', render: (item) => formatDate(item.created_at ?? item.timestamp) },
    {
      key: 'actions',
      label: 'Actions',
      render: (item) => {
        const id = getString(item, ['id'], '');
        return (
          <AnchorButton variant="secondary" href={buildDetailHref('evidence-detail', id)} aria-label={`View evidence detail for ${id}`}>
            View
          </AnchorButton>
        );
      }
    }
  ];

  const chainPreview = buildEvidenceChainExport({
    evidence: data.evidence,
    runs: data.runs,
    findings: data.findings
  });
  const chainLinks = chainPreview.payload.chain;
  const visibleChainLinks = showFullEvidenceChain ? chainLinks : chainLinks.slice(0, evidenceChainCap);
  const chainHasMore = chainLinks.length > evidenceChainCap;

  const digestSha = getString(evidenceCustodyPreview ?? {}, ['content_sha256'], '');
  const linkedRunCount = new Set(data.evidence.map((e) => getString(e, ['test_run_id'], '')).filter(Boolean)).size;
  const openFindingCount = data.findings.filter((f) => getString(f, ['status']) === 'open').length;

  const evidenceChainFooter = data.evidence.length > 0 ? (
    <div className="vault-card-footer stack-tight">
      <CardTitle>Evidence chain</CardTitle>
      <p className="muted small">
        Correlated links between vault records, runs, and findings
        {chainHasMore && !showFullEvidenceChain ? ` (showing first ${evidenceChainCap} of ${chainLinks.length})` : ''}.
      </p>
      <ol className="dashboard-link-list">
        {visibleChainLinks.map((link) => {
          const evidenceId = String(link.evidence_id ?? '');
          const runId = String(link.test_run_id ?? '');
          const evidenceRecord = data.evidence.find((entry) => getString(entry, ['id']) === evidenceId);
          const evidenceLabel = evidenceRecord
            ? getString(evidenceRecord, ['label', 'kind', 'signal_type'], 'Evidence record')
            : 'Evidence record';
          const verdict = String(link.verdict ?? 'pending');
          return (
            <li key={evidenceId}>
              <div className="stack-tight">
                <AnchorButton variant="secondary" href={buildDetailHref('evidence-detail', evidenceId)}>{evidenceLabel}</AnchorButton>
                <span className="muted small">
                  <code>{evidenceId}</code>
                  {runId ? (
                    <> · run <AnchorButton variant="ghost" href={buildDetailHref('run-detail', runId)}>{runDisplayLabelForId(data.checks, data.runs, runId)}</AnchorButton></>
                  ) : ' · run —'}
                  {' · '}
                  <Badge tone={verdictBadgeTone(verdict)}>{formatVerdictLabel(verdict)}</Badge>
                </span>
              </div>
            </li>
          );
        })}
      </ol>
      {chainHasMore ? (
        <div className="form-actions">
          <Button variant="ghost" size="sm" type="button" aria-label={showFullEvidenceChain ? 'Show fewer evidence chain links' : 'View all evidence chain links'} onClick={() => setShowFullEvidenceChain((open) => !open)}>
            {showFullEvidenceChain ? 'Show fewer' : `View all (${chainLinks.length})`}
          </Button>
        </div>
      ) : null}
    </div>
  ) : null;

  return (
    <div className="content">
      <PageHeader route="evidence" />
      {(message || error) && <div className={error ? 'form-banner error' : 'form-banner neutral'}>{error || message}</div>}
      {clipboardNotice ? <div className="form-banner info" role="status">{clipboardNotice}</div> : null}
      {exportPartialMissCount > 0 ? (
        <div className="form-banner error">Export complete with {exportPartialMissCount} run(s) missing verdict detail.</div>
      ) : null}
      <Card>
        <CardHeader>
          <div>
            <CardTitle>Evidence vault</CardTitle>
            <CardDescription>
              Metadata-only custody records from probes, agents, and correlated runs.
              {' '}
              <span className="muted small">
                {data.evidence.length} records · {linkedRunCount} linked runs · {openFindingCount} open findings
              </span>
            </CardDescription>
          </div>
          {data.evidence.length > 0 ? (
            <div className="row-actions row-actions--spaced">
              <Button loading={busy === 'export-evidence-chain'} disabled={busy !== ''} onClick={() => void exportEvidenceChain()}>Export chain JSON</Button>
              <Button
                variant="secondary"
                disabled={!exportOutput}
                onClick={() => {
                  void navigator.clipboard.writeText(exportOutput).then(() => setClipboardNotice('Export JSON copied to clipboard.')).catch(() => setClipboardNotice('Clipboard access denied.'));
                }}
              >
                Copy export JSON
              </Button>
            </div>
          ) : null}
        </CardHeader>
        <CardContent>
          <DataTable
            columns={evidenceColumns}
            items={data.evidence}
            empty={(
              <EmptyState
                icon={FileCheck2}
                title="No evidence yet."
                body="Evidence appears after probe and agent observations correlate."
                actionLabel="View test runs"
                actionHref="#runs"
              />
            )}
          />
          {evidenceChainFooter}
        </CardContent>
      </Card>
      {data.evidence.length > 0 && (showEvidenceExportCenter || busy === 'export-evidence-chain' || exportOutput || evidenceCustodyPreview) ? (
        <Card>
          <CardHeader>
            <CardTitle>Export preview</CardTitle>
            <CardDescription>Custody digest verification and export summary — no raw payloads rendered.</CardDescription>
          </CardHeader>
          <CardContent className="stack-tight">
            {busy === 'export-evidence-chain' ? (
              <div className="kv-list" aria-busy="true" aria-label="Building export preview">
                {Array.from({ length: 4 }, (_, index) => (
                  <div key={index}><span className="skeleton skeleton-text" /><span className="skeleton skeleton-text" /></div>
                ))}
              </div>
            ) : (
              <div className="kv-list kv-list--compact">
                {summarizeEvidenceExport(chainPreview).map(([label, value]) => (
                  <div key={label}><span>{label}</span><strong>{value}</strong></div>
                ))}
              </div>
            )}
            {evidenceCustodyPreview ? (
              <div className="kv-list kv-list--compact">
                <div><span>Custody status</span><strong>{evidenceCustodyPreview.ok === true ? 'Digest verified' : getString(evidenceCustodyPreview, ['error'], 'verification failed')}</strong></div>
                <div><span>Schema</span><strong>{getString(evidenceCustodyPreview, ['schema_version'])}</strong></div>
                <div><span>Digest</span><strong><code className="small">{digestSha ? `${digestSha.slice(0, 16)}…` : '—'}</code></strong></div>
              </div>
            ) : <p className="muted">Run export from the vault header to verify custody digest.</p>}
            {digestSha ? (
              <Button
                variant="ghost"
                aria-label="Copy full content digest to clipboard"
                onClick={() => {
                  void navigator.clipboard.writeText(digestSha).then(() => setClipboardNotice('Full digest copied to clipboard.')).catch(() => setClipboardNotice('Clipboard access denied.'));
                }}
              >
                Copy full digest
              </Button>
            ) : null}
            {exportOutput ? (
              <>
                <p className="muted">{message || 'Evidence chain exported'} — {exportOutput.length} chars</p>
                <Button variant="ghost" size="sm" type="button" onClick={() => setShowTechnicalExport((open) => !open)}>
                  {showTechnicalExport ? 'Hide technical details' : 'View technical details'}
                </Button>
                {showTechnicalExport ? (
                  <pre className="codeblock">{exportOutput.slice(0, 2400)}{exportOutput.length > 2400 ? '\n…' : ''}</pre>
                ) : null}
              </>
            ) : null}
          </CardContent>
        </Card>
      ) : null}
    </div>
  );
}

export function PostureSurfacePage({
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
  const [output, setOutput] = useState('');
  const [showTechnicalActionResult, setShowTechnicalActionResult] = useState(false);
  const [showMoreCreateOptions, setShowMoreCreateOptions] = useState(false);
  const [deliverChannel, setDeliverChannel] = useState<string>('webhook');
  const [selectedActionItemId, setSelectedActionItemId] = useState('');
  const [approveTargetGroupByCandidate, setApproveTargetGroupByCandidate] = useState<Record<string, string>>({});
  const [rejectReasonByCandidate, setRejectReasonByCandidate] = useState<Record<string, string>>({});
  const [wafAssetTargetGroupId, setWafAssetTargetGroupId] = useState('');
  const [wafAssetTargets, setWafAssetTargets] = useState<DataItem[]>([]);
  const [wafAssetTargetsLoading, setWafAssetTargetsLoading] = useState(false);
  const [wafAssetTargetsError, setWafAssetTargetsError] = useState('');
  const [wafPostureTab, setWafPostureTab] = useState<WafPostureSurfaceTabId>('overview');
  const [showWafDeclareAssetForm, setShowWafDeclareAssetForm] = useState(false);
  const [driftScanLatest, setDriftScanLatest] = useState<DataItem | null>(null);
  const [driftScanLatestLoading, setDriftScanLatestLoading] = useState(false);
  const [driftScanLatestError, setDriftScanLatestError] = useState('');
  const [sessionRetestsByDrift, setSessionRetestsByDrift] = useState<Record<string, DataItem>>({});
  const [exceptionAssetId, setExceptionAssetId] = useState('');
  const [showCveIngestForm, setShowCveIngestForm] = useState(false);
  const [showSupplyChainCreateForm, setShowSupplyChainCreateForm] = useState(false);
  const [showRemediationCreateForm, setShowRemediationCreateForm] = useState(false);
  const [showRemediationDeliverPanel, setShowRemediationDeliverPanel] = useState(false);
  const [showDiscoveryDeclareForm, setShowDiscoveryDeclareForm] = useState(false);
  const [discoveryQueueTab, setDiscoveryQueueTab] = useState<'inbox' | 'candidates' | 'entities'>('candidates');
  const [cveFilterSeverity, setCveFilterSeverity] = useState('all');
  const [cveFilterStage, setCveFilterStage] = useState('all');
  const [cveFilterKev, setCveFilterKev] = useState(false);
  const [supplyChainFilterState, setSupplyChainFilterState] = useState('all');
  const [supplyChainFilterSeverity, setSupplyChainFilterSeverity] = useState('all');
  const [wafOpsSectionOpen, setWafOpsSectionOpen] = useState<Record<string, boolean>>({
    driftScan: true,
    driftEvents: false,
    validationPlans: false,
    exceptions: false
  });
  const [wafTargetsRetryToken, setWafTargetsRetryToken] = useState(0);
  const [driftLatestRetryToken, setDriftLatestRetryToken] = useState(0);
  const wafEnabled = featureEnabled(data, 'waf_posture');
  const discoveryEnabled = featureEnabled(data, 'external_discovery');
  const requiresWaf = ['waf-posture', 'cve-pipeline', 'supply-chain', 'remediation'].includes(route);
  const enabled = route === 'discovery' ? discoveryEnabled : wafEnabled;
  const protectedPercent = getNestedNumber(data.wafCoverage, ['percentages', 'protected'], 0);
  useEffect(() => {
    if (route !== 'waf-posture' || !wafAssetTargetGroupId) {
      setWafAssetTargets([]);
      setWafAssetTargetsError('');
      return;
    }
    let cancelled = false;
    setWafAssetTargetsLoading(true);
    setWafAssetTargetsError('');
    requestJson(config, session, `/v1/target-groups/${encodeURIComponent(wafAssetTargetGroupId)}`)
      .then((detail) => {
        if (cancelled) return;
        const targets = Array.isArray((detail as DataItem).targets) ? (detail as DataItem).targets as DataItem[] : [];
        setWafAssetTargets(targets);
      })
      .catch((err) => {
        if (!cancelled) {
          setWafAssetTargets([]);
          setWafAssetTargetsError(err instanceof Error ? err.message : 'Could not load targets for the selected group.');
        }
      })
      .finally(() => {
        if (!cancelled) setWafAssetTargetsLoading(false);
      });
    return () => { cancelled = true; };
  }, [route, wafAssetTargetGroupId, config, session, wafTargetsRetryToken]);

  useEffect(() => {
    if (route !== 'waf-posture' || !wafEnabled) {
      setDriftScanLatest(null);
      setDriftScanLatestError('');
      return;
    }
    let cancelled = false;
    setDriftScanLatestLoading(true);
    setDriftScanLatestError('');
    requestJson(config, session, '/v1/waf/drift-scans/latest')
      .then((payload) => {
        if (cancelled) return;
        const scan = (payload as { scan_result?: DataItem | null }).scan_result;
        setDriftScanLatest(scan && typeof scan === 'object' ? scan as DataItem : null);
      })
      .catch((err) => {
        if (!cancelled) {
          setDriftScanLatest(null);
          setDriftScanLatestError(err instanceof Error ? err.message : 'Could not load latest drift scan.');
        }
      })
      .finally(() => {
        if (!cancelled) setDriftScanLatestLoading(false);
      });
    return () => { cancelled = true; };
  }, [route, wafEnabled, config, session, data.wafDriftEvents.length, driftLatestRetryToken]);

  useEffect(() => {
    setShowMoreCreateOptions(false);
  }, [route]);

  useEffect(() => {
    if (wafPostureTab !== 'overview') {
      setShowWafDeclareAssetForm(false);
    }
  }, [wafPostureTab]);

  function resolveTargetGroupId(candidateId: string, pickerState: Record<string, string>) {
    return pickerState[candidateId] ?? '';
  }

  function toggleWafOpsSection(section: string) {
    setWafOpsSectionOpen((current) => ({ ...current, [section]: !current[section] }));
  }

  async function handleAction(label: string, action: () => Promise<unknown>, success: string) {
    const result = await runAction(setBusy, setError, setMessage, label, action, success, onRefresh);
    if (result) setOutput(JSON.stringify(result, null, 2));
    return result;
  }

  const routeConfig: Record<string, {
    metricCards: Array<{ label: string; value: string | number; sub: string; icon: typeof Activity; tone: 'default' | 'success' | 'warn' | 'danger' | 'info' | 'muted' }>;
    columns: TableColumn<DataItem>[];
    items: DataItem[];
    emptyTitle: string;
    emptyBody: string;
  }> = {
    'waf-posture': {
      metricCards: [
        { label: 'WAF assets', value: data.wafAssets.length, sub: 'Declared protected services', icon: ShieldCheck, tone: 'info' },
        { label: 'Protected', value: `${Math.round(protectedPercent)}%`, sub: `${getNumber(data.wafCoverage ?? {}, ['protected'])}/${getNumber(data.wafCoverage ?? {}, ['total_assets'])} assets`, icon: CheckCircle2, tone: protectedPercent >= 80 ? 'success' : 'warn' },
        { label: 'Drift events', value: data.wafDriftEvents.length, sub: 'Posture changes', icon: TriangleAlert, tone: data.wafDriftEvents.length > 0 ? 'warn' : 'success' }
      ],
      columns: [
        { key: 'asset', label: 'Asset', render: (item) => getString(item, ['canonical_url', 'display_ref', 'id']) },
        {
          key: 'status',
          label: 'Status',
          render: (item) => {
            const status = getString(item, ['status'], 'unknown');
            return <Badge tone={wafAssetStatusBadgeTone(status)}>{formatCoverageStatusLabel(status)}</Badge>;
          }
        },
        { key: 'vendor', label: 'Vendor', render: (item) => getString(item, ['detected_vendor', 'expected_vendor_hint', 'provider']) },
        { key: 'criticality', label: 'Criticality', render: (item) => getString(item, ['business_criticality', 'criticality']) },
        { key: 'updated', label: 'Updated', render: (item) => formatDate(item.updated_at ?? item.created_at) },
        {
          key: 'detail',
          label: 'Detail',
          render: (item) => {
            const id = getString(item, ['id'], '');
            return id ? <AnchorButton size="sm" variant="secondary" href={buildDetailHref('waf-asset-detail', id)}>Open</AnchorButton> : null;
          }
        }
      ],
      items: data.wafAssets,
      emptyTitle: 'No WAF assets recorded.',
      emptyBody: 'Create a declared WAF asset or import from an approved connector snapshot.'
    },
    'cve-pipeline': {
      metricCards: [
        { label: 'CVE items', value: data.cvePipeline.length, sub: 'Pipeline records', icon: TriangleAlert, tone: data.cvePipeline.length > 0 ? 'warn' : 'success' },
        { label: 'Known exploited', value: data.cvePipeline.filter((item) => item.known_exploited === true).length, sub: 'KEV flagged', icon: Siren, tone: 'danger' },
        { label: 'Safe validations', value: data.wafValidations.length, sub: 'Tenant-wide WAF validation runs (not pipeline stage)', icon: ListChecks, tone: 'info' }
      ],
      columns: [
        { key: 'cve', label: 'CVE', render: (item) => getString(item, ['cve_id', 'id']) },
        { key: 'severity', label: 'Severity', render: (item) => <Badge tone={['critical', 'high'].includes(getString(item, ['severity']).toLowerCase()) ? 'danger' : 'warn'}>{formatSeverityLabel(getString(item, ['severity']))}</Badge> },
        { key: 'kev', label: 'KEV', render: (item) => item.known_exploited === true ? <Badge tone="danger">KEV</Badge> : <span className="muted">—</span> },
        {
          key: 'stage',
          label: 'Stage',
          render: (item) => {
            const stage = getString(item, ['stage', 'status']);
            return <Badge tone={cveStageBadgeTone(stage)}>{formatSnakeLabel(stage)}</Badge>;
          }
        },
        {
          key: 'detail',
          label: 'Detail',
          render: (item) => {
            const id = getString(item, ['id'], '');
            return id ? <AnchorButton size="sm" variant="secondary" href={buildDetailHref('cve-detail', id)}>Open</AnchorButton> : null;
          }
        }
      ],
      items: data.cvePipeline,
      emptyTitle: 'No CVE pipeline records.',
      emptyBody: 'Ingest a feed or create a CVE item manually.'
    },
    'supply-chain': {
      metricCards: [
        { label: 'Risks', value: data.supplyChainRisks.length, sub: 'Supply-chain records', icon: Network, tone: data.supplyChainRisks.length > 0 ? 'warn' : 'success' },
        { label: 'High severity', value: data.supplyChainRisks.filter((item) => ['critical', 'high'].includes(getString(item, ['severity']).toLowerCase())).length, sub: 'Needs review', icon: TriangleAlert, tone: 'danger' },
        { label: 'Authorized phases', value: data.supplyChainRisks.filter((item) => Array.isArray(item.phase_authorizations) && item.phase_authorizations.length > 0).length, sub: 'Customer-approved', icon: FileCheck2, tone: 'info' }
      ],
      columns: [
        { key: 'host', label: 'Host', render: (item) => getString(item, ['hostname', 'id']) },
        {
          key: 'type',
          label: 'Exposure',
          render: (item) => {
            const exposureType = getString(item, ['exposure_type']);
            const meta = SUPPLY_CHAIN_EXPOSURE_TYPES.find((entry) => entry.id === exposureType);
            return meta?.label ?? formatSnakeLabel(exposureType);
          }
        },
        { key: 'severity', label: 'Severity', render: (item) => <Badge tone={['critical', 'high'].includes(getString(item, ['severity']).toLowerCase()) ? 'danger' : 'warn'}>{formatSeverityLabel(getString(item, ['severity']))}</Badge> },
        {
          key: 'state',
          label: 'State',
          render: (item) => {
            const state = getString(item, ['state']);
            return <Badge tone={supplyChainStateBadgeTone(state)}>{formatSupplyChainStateLabel(state)}</Badge>;
          }
        },
        {
          key: 'detail',
          label: 'Detail',
          render: (item) => {
            const id = getString(item, ['id'], '');
            return id ? <AnchorButton size="sm" variant="secondary" href={buildDetailHref('supply-chain-detail', id)}>Open</AnchorButton> : null;
          }
        }
      ],
      items: data.supplyChainRisks,
      emptyTitle: 'No supply-chain risks recorded.',
      emptyBody: 'Create a metadata-only supply-chain risk record.'
    },
    remediation: {
      metricCards: [
        { label: 'Action items', value: data.wafActionItems.length, sub: 'Remediation tasks', icon: ClipboardList, tone: data.wafActionItems.length > 0 ? 'warn' : 'success' },
        { label: 'Open', value: data.wafActionItems.filter((item) => !CLOSED_ACTION_ITEM_STATUSES.has(getString(item, ['status']).toLowerCase())).length, sub: 'Not closed', icon: Clock3, tone: 'warn' },
        { label: 'Exceptions', value: data.wafExceptions.length, sub: 'Approved exceptions', icon: FileCheck2, tone: 'info' }
      ],
      columns: [
        { key: 'title', label: 'Action item', render: (item) => getString(item, ['title', 'id']) },
        { key: 'severity', label: 'Severity', render: (item) => <Badge tone={['critical', 'high'].includes(getString(item, ['severity']).toLowerCase()) ? 'danger' : 'warn'}>{formatSeverityLabel(getString(item, ['severity']))}</Badge> },
        {
          key: 'status',
          label: 'Status',
          render: (item) => {
            const id = getString(item, ['action_item_id', 'id'], '');
            const status = getString(item, ['status'], 'open');
            return (
              <span onClick={(event) => event.stopPropagation()}>
                <Select
                  className="inline-select-control"
                  label={`Remediation status for ${getString(item, ['title', 'id'], id)}`}
                  value={status}
                  disabled={busy !== ''}
                  options={ACTION_ITEM_STATUSES.map((value) => ({ value, label: formatRemediationStatusLabel(value) }))}
                  onChange={(nextStatus) => {
                    if (nextStatus === status) return;
                    if (!window.confirm(`Change remediation status to "${formatRemediationStatusLabel(nextStatus)}"? This updates SLA and tracking.`)) {
                      return;
                    }
                    void handleAction(`patch-action-${id}`, () => requestJson(config, session, `/v1/waf/action-items/${id}`, { method: 'PATCH', body: { status: nextStatus } }), 'Action item status updated.');
                  }}
                />
              </span>
            );
          }
        },
        {
          key: 'actions',
          label: 'Actions',
          render: (item) => {
            const id = getString(item, ['action_item_id', 'id'], '');
            return (
              <div className="row-actions">
                <Button
                  size="sm"
                  variant="secondary"
                  loading={busy === `deliver-${id}`}
                  disabled={busy !== ''}
                  onClick={(event) => {
                    event.stopPropagation();
                    setSelectedActionItemId(id);
                    setShowRemediationDeliverPanel(true);
                    window.requestAnimationFrame(() => {
                      scrollElementIntoView(document.getElementById('remediation-delivery-card'), 'start');
                    });
                  }}
                >
                  Deliver
                </Button>
              </div>
            );
          }
        }
      ],
      items: data.wafActionItems,
      emptyTitle: 'No remediation action items.',
      emptyBody: 'Create action items from WAF findings.'
    },
    discovery: {
      metricCards: [
        { label: 'Entities', value: data.discoveryEntities.length, sub: 'Approved entities', icon: Network, tone: 'info' },
        { label: 'Candidates', value: data.discoveryCandidates.length, sub: 'Awaiting decision', icon: ScanSearch, tone: data.discoveryCandidates.length > 0 ? 'warn' : 'success' },
        { label: 'Inbox', value: data.discoveryInbox.length, sub: 'Pending review', icon: ClipboardList, tone: data.discoveryInbox.length > 0 ? 'warn' : 'success' }
      ],
      columns: [],
      items: [],
      emptyTitle: 'No discovery records.',
      emptyBody: 'Declare an entity or ingest passive discovery candidates.'
    }
  };

  const tableConfig = routeConfig[route] ?? routeConfig['waf-posture'];

  const filteredCvePipeline = useMemo(() => data.cvePipeline.filter((item) => {
    if (cveFilterKev && item.known_exploited !== true) return false;
    if (cveFilterSeverity !== 'all' && getString(item, ['severity']).toLowerCase() !== cveFilterSeverity) return false;
    if (cveFilterStage !== 'all' && getString(item, ['stage', 'status']).toLowerCase() !== cveFilterStage) return false;
    return true;
  }), [data.cvePipeline, cveFilterKev, cveFilterSeverity, cveFilterStage]);

  const filteredSupplyChainRisks = useMemo(() => data.supplyChainRisks.filter((item) => {
    if (supplyChainFilterState !== 'all' && getString(item, ['state']).toLowerCase() !== supplyChainFilterState) return false;
    if (supplyChainFilterSeverity !== 'all' && getString(item, ['severity']).toLowerCase() !== supplyChainFilterSeverity) return false;
    return true;
  }), [data.supplyChainRisks, supplyChainFilterState, supplyChainFilterSeverity]);

  const discoveryQueueItems = discoveryQueueTab === 'inbox'
    ? data.discoveryInbox
    : discoveryQueueTab === 'entities'
      ? data.discoveryEntities
      : data.discoveryCandidates;

  const discoveryQueueColumns: TableColumn<DataItem>[] = discoveryQueueTab === 'entities'
    ? [
      { key: 'entity', label: 'Entity', render: (item) => getString(item, ['display_name', 'name', 'entity_id', 'id']) },
      { key: 'type', label: 'Type', render: (item) => getString(item, ['entity_type', 'type']) },
      {
        key: 'state',
        label: 'State',
        render: (item) => {
          const state = getString(item, ['state'], 'entity');
          return <Badge tone={discoveryEntityStateBadgeTone(state)}>{formatDiscoveryStateLabel(state)}</Badge>;
        }
      },
      {
        key: 'actions',
        label: 'Actions',
        render: (item) => {
          const id = getString(item, ['entity_id', 'id'], '');
          return id ? <AnchorButton size="sm" variant="secondary" href={buildDetailHref('discovery-entity', id)}>Detail</AnchorButton> : null;
        }
      }
    ]
    : [
      { key: 'candidate', label: discoveryQueueTab === 'inbox' ? 'Inbox item' : 'Candidate', render: (item) => getString(item, ['value', 'hostname', 'entity_id', 'id']) },
      { key: 'type', label: 'Type', render: (item) => getString(item, ['entity_type', 'candidate_type', 'type']) },
      {
        key: 'state',
        label: 'State',
        render: (item) => {
          const state = getString(item, ['state'], 'pending');
          return <Badge tone={discoveryEntityStateBadgeTone(state)}>{formatDiscoveryStateLabel(state)}</Badge>;
        }
      },
      {
        key: 'actions',
        label: 'Actions',
        render: (item) => {
          const id = getString(item, ['id', 'entity_id'], '');
          const rowBusy = busy === `approve-${id}` || busy === `reject-${id}` || busy === `import-${id}`;
          const state = getString(item, ['state'], '');
          return (
            <div className={discoveryQueueTab === 'candidates' ? 'candidate-review-actions' : 'row-actions'}>
              {id ? <AnchorButton size="sm" variant="secondary" href={buildDetailHref('discovery-entity', id)}>Detail</AnchorButton> : null}
              {discoveryQueueTab === 'candidates' && state !== 'approved' && state !== 'approved_target' && state !== 'rejected' ? (
                <>
                  <span onClick={(event) => event.stopPropagation()}>
                    <Select
                      className="inline-select-control"
                      label={`Target group for ${getString(item, ['value', 'hostname'], id)}`}
                      value={approveTargetGroupByCandidate[id] ?? ''}
                      disabled={rowBusy || data.targetGroups.length === 0}
                      options={[
                        { value: '', label: 'Select target group' },
                        ...data.targetGroups.map((group) => ({
                          value: getString(group, ['id']),
                          label: getString(group, ['name', 'id'])
                        }))
                      ]}
                      onChange={(nextValue) => setApproveTargetGroupByCandidate((current) => ({ ...current, [id]: nextValue }))}
                    />
                  </span>
                  <Button
                    size="sm"
                    variant="ghost"
                    loading={busy === `approve-${id}`}
                    disabled={rowBusy || !resolveTargetGroupId(id, approveTargetGroupByCandidate)}
                    onClick={() => {
                      const targetGroupId = resolveTargetGroupId(id, approveTargetGroupByCandidate);
                      if (!targetGroupId) {
                        setError('Select a target group before approving this candidate.');
                        return;
                      }
                      if (!window.confirm('Approve this discovery candidate into the selected target group?')) return;
                      void handleAction(`approve-${id}`, () => requestJson(config, session, `/v1/discovery/candidates/${id}/approve`, { method: 'POST', body: { target_group_id: targetGroupId } }), 'Candidate approved.');
                    }}
                  >
                    Approve
                  </Button>
                  <span onClick={(event) => event.stopPropagation()}>
                    <Select
                      className="inline-select-control"
                      label={`Rejection reason for ${getString(item, ['value', 'hostname'], id)}`}
                      value={rejectReasonByCandidate[id] ?? 'not_in_scope'}
                      disabled={rowBusy}
                      options={DISCOVERY_REJECT_REASONS.map((reason) => ({ value: reason.id, label: reason.label }))}
                      onChange={(nextValue) => setRejectReasonByCandidate((current) => ({ ...current, [id]: nextValue }))}
                    />
                  </span>
                  <Button
                    size="sm"
                    variant="ghost"
                    loading={busy === `reject-${id}`}
                    disabled={rowBusy}
                    onClick={() => {
                      const reason = rejectReasonByCandidate[id] ?? 'not_in_scope';
                      const reasonLabel = DISCOVERY_REJECT_REASONS.find((entry) => entry.id === reason)?.label ?? formatSnakeLabel(reason);
                      if (!window.confirm(`Reject this discovery candidate as "${reasonLabel}"?`)) return;
                      void handleAction(`reject-${id}`, () => requestJson(config, session, `/v1/discovery/candidates/${id}/reject`, { method: 'POST', body: { reason } }), 'Candidate rejected.');
                    }}
                  >
                    Reject
                  </Button>
                </>
              ) : null}
            </div>
          );
        }
      }
    ];
  const targetGroupNameById = Object.fromEntries(
    data.targetGroups.map((group) => [getString(group, ['id'], ''), getString(group, ['name', 'id'], '')])
  );
  const wafAssetColumns: TableColumn<DataItem>[] = [
    {
      key: 'asset',
      label: 'Asset',
      render: (item) => (
        <div className="stack-tight">
          <strong>{getString(item, ['canonical_url', 'display_ref', 'hostname', 'id'])}</strong>
          {getString(item, ['owner_hint']) ? <span className="muted small">{getString(item, ['owner_hint'])}</span> : null}
        </div>
      )
    },
    {
      key: 'status',
      label: 'Status',
      render: (item) => {
        const status = getString(item, ['status', 'posture_status'], 'unknown');
        return <Badge tone={wafAssetStatusBadgeTone(status)}>{formatCoverageStatusLabel(status)}</Badge>;
      }
    },
    { key: 'vendor', label: 'Vendor', render: (item) => getString(item, ['detected_vendor', 'expected_vendor_hint', 'provider']) },
    {
      key: 'pass-rate',
      label: 'Pass rate',
      render: (item) => {
        const effectiveness = getNestedItem(item, ['effectiveness']);
        const passRate = typeof effectiveness?.scenario_pass_rate === 'number'
          ? effectiveness.scenario_pass_rate
          : computeWafAssetPassRate(getString(item, ['id'], ''), data.wafValidations);
        const ruleHealth = formatWafRuleHealthDisplay(effectiveness);
        return (
          <div className="stack-tight">
            <span>{formatWafPassRateDisplay(passRate)}</span>
            {ruleHealth && ruleHealth !== '—' ? <span className="muted small">{ruleHealth}</span> : null}
          </div>
        );
      }
    },
    { key: 'target-group', label: 'Target group', render: (item) => targetGroupNameById[getString(item, ['target_group_id'], '')] || getString(item, ['target_group_id']) },
    {
      key: 'detail',
      label: 'Detail',
      render: (item) => {
        const id = getString(item, ['id'], '');
        return id ? <AnchorButton size="sm" variant="secondary" href={buildDetailHref('waf-asset-detail', id)}>Open</AnchorButton> : null;
      }
    }
  ];
  const roadmapTiers = (data.wafRiskRoadmap?.tiers as Record<string, DataItem[]> | undefined) ?? {};
  const roadmapMethod = getString(data.wafRiskRoadmap ?? {}, ['method'], '');
  const roadmapGeneratedAt = formatDate(data.wafRiskRoadmap?.generated_at);
  const roadmapItemCount = roadmapTotalItems(roadmapTiers);

  function renderWafRoadmapPanel() {
    if (!roadmapItemCount) {
      const emptyCopy = roadmapMethod
        ? 'No roadmap items yet. Declare assets and finalize safe validations so risk scoring can rank deployment priorities.'
        : 'Risk scoring has not produced roadmap tiers yet. Finalize validations on declared assets to seed risk scores.';
      return (
        <Card>
          <CardHeader>
            <CardTitle>Deployment roadmap</CardTitle>
            <CardDescription>Tiered WAF deployment priorities ranked from coverage risk scoring.</CardDescription>
          </CardHeader>
          <CardContent>
            <EmptyState icon={ShieldCheck} title="Roadmap awaiting risk scores" body={emptyCopy} />
          </CardContent>
        </Card>
      );
    }

    return (
      <Card>
        <CardHeader>
          <CardTitle>Deployment roadmap</CardTitle>
          <CardDescription>
            Tiered deployment priorities · generated {roadmapGeneratedAt}{roadmapMethod ? ` · scoring method ${roadmapMethod}` : ''}
          </CardDescription>
        </CardHeader>
        <CardContent className="tab-panel-layout">
          {roadmapTierIds().map((tierId) => {
            const items = roadmapTiers[tierId] ?? [];
            const meta = roadmapTierMeta(tierId);
            const columns: TableColumn<DataItem>[] = [
              { key: 'asset', label: 'Asset', render: (item) => getString(item, ['hostname', 'waf_asset_id', 'canonical_url']) },
              { key: 'owner', label: 'Owner', render: (item) => getString(item, ['owner_hint']) },
              { key: 'risk', label: 'Risk', render: (item) => getString(item, ['risk_score']) },
              {
                key: 'status',
                label: 'Status',
                render: (item) => {
                  const status = getString(item, ['posture_status'], 'unknown');
                  return <Badge tone={wafAssetStatusBadgeTone(status)}>{formatCoverageStatusLabel(status)}</Badge>;
                }
              },
              {
                key: 'gap',
                label: 'Primary gap',
                render: (item) => {
                  const codes = Array.isArray(item.primary_reason_codes) ? item.primary_reason_codes as string[] : [];
                  return codes.length ? codes.join(', ') : '—';
                }
              },
              { key: 'action', label: 'Recommended action', render: (item) => getString(item, ['recommended_action'], 'Review WAF posture gap.') },
              { key: 'vendor', label: 'Vendor', render: (item) => getString(item, ['detected_vendor'], 'none') }
            ];
            return (
              <div key={tierId}>
                <p className="roadmap-tier-heading">{meta.label} <span className="muted">({meta.window})</span></p>
                <DataTable
                  columns={columns}
                  items={items}
                  empty={<EmptyState icon={ShieldCheck} title={`No assets in ${meta.label}`} body="This tier is empty for the current risk snapshot." />}
                />
              </div>
            );
          })}
        </CardContent>
      </Card>
    );
  }

  function rememberRetest(driftEventId: string, retest: DataItem | null | undefined) {
    if (!driftEventId || !retest || typeof retest !== 'object') return;
    setSessionRetestsByDrift((current) => ({ ...current, [driftEventId]: retest }));
  }

  function resolveDriftRetest(driftEventId: string) {
    return sessionRetestsByDrift[driftEventId] ?? retestForDriftEvent(data.wafRetests, driftEventId);
  }

  function defaultExceptionExpiryIso(daysAhead = 90) {
    const expires = new Date();
    expires.setUTCDate(expires.getUTCDate() + daysAhead);
    return expires.toISOString();
  }

  function renderWafOperatorPanels() {
    const driftColumns: TableColumn<DataItem>[] = [
      { key: 'type', label: 'Drift type', render: (item) => getString(item, ['drift_type', 'reason_code', 'type']) },
      { key: 'asset', label: 'Asset', render: (item) => getString(item, ['waf_asset_id', 'canonical_url', 'hostname']) },
      { key: 'severity', label: 'Severity', render: (item) => <Badge tone={['critical', 'high'].includes(getString(item, ['severity']).toLowerCase()) ? 'danger' : 'warn'}>{formatSeverityLabel(getString(item, ['severity']))}</Badge> },
      { key: 'seen', label: 'First seen', render: (item) => formatDate(item.first_seen_at ?? item.created_at) },
      {
        key: 'status',
        label: 'Status',
        render: (item) => {
          const id = getString(item, ['id'], '');
          const status = getString(item, ['status'], 'open');
          return (
            <span onClick={(event) => event.stopPropagation()}>
              <Select
                className="inline-select-control"
                label={`Drift event status for ${getString(item, ['drift_type', 'reason_code', 'type'], id)}`}
                value={status}
                disabled={busy !== ''}
                options={DRIFT_EVENT_STATUSES.map((value) => ({ value, label: formatSnakeLabel(value) }))}
                onChange={(nextStatus) => {
                  if (nextStatus === status) return;
                  if (!window.confirm(`Update drift event status to "${formatSnakeLabel(nextStatus)}"?`)) return;
                  void handleAction(`patch-drift-${id}`, () => requestJson(config, session, `/v1/waf/drift-events/${id}`, {
                    method: 'PATCH',
                    body: { status: nextStatus }
                  }), 'Drift status updated.');
                }}
              />
            </span>
          );
        }
      },
      {
        key: 'retest',
        label: 'Retest',
        render: (item) => {
          const driftId = getString(item, ['id'], '');
          const retest = resolveDriftRetest(driftId);
          const retestId = getString(retest, ['id'], '');
          const retestStatus = getString(retest, ['status'], 'none');
          return (
            <div className="stack-tight">
              {retestId ? (
                <span className="muted small">
                  <code>{retestId}</code>
                  {' · '}
                  <Badge tone={runStatusBadgeTone(retestStatus)}>{formatRunStatusLabel(retestStatus)}</Badge>
                </span>
              ) : <span className="muted small">No retest yet</span>}
              <div className="row-actions">
                <Button
                  size="sm"
                  variant="secondary"
                  loading={busy === `drift-retest-${driftId}`}
                  disabled={busy !== ''}
                  onClick={() => {
                    if (!window.confirm('Request a safe drift retest for this event? Validation will run for the linked WAF asset scope.')) return;
                    void handleAction(`drift-retest-${driftId}`, async () => {
                      const payload = await requestJson(config, session, `/v1/waf/drift-events/${driftId}/retest`, { method: 'POST', body: {} }) as { retest_request?: DataItem };
                      rememberRetest(driftId, payload?.retest_request);
                      return payload;
                    }, 'Retest requested.');
                  }}
                >
                  Request
                </Button>
                {retestId ? (
                  <>
                    <Button
                      size="sm"
                      variant="ghost"
                      loading={busy === `retest-exec-${retestId}`}
                      disabled={busy !== ''}
                      onClick={() => {
                        if (!window.confirm('Execute this drift retest now? This will run validation for the drift item.')) return;
                        void handleAction(`retest-exec-${retestId}`, async () => {
                          const payload = await requestJson(config, session, `/v1/waf/retests/${retestId}/execute`, { method: 'POST', body: {} }) as { retest_request?: DataItem };
                          rememberRetest(driftId, payload?.retest_request ?? retest);
                          return payload;
                        }, 'Retest execution delegated.');
                      }}
                    >
                      Execute
                    </Button>
                    <Button
                      size="sm"
                      variant="ghost"
                      loading={busy === `retest-complete-${retestId}`}
                      disabled={busy !== ''}
                      onClick={() => {
                        if (!window.confirm('Complete this drift retest? This will close the drift retest workflow.')) return;
                        void handleAction(`retest-complete-${retestId}`, async () => {
                          const payload = await requestJson(config, session, `/v1/waf/retests/${retestId}/complete`, { method: 'POST' }) as { retest_request?: DataItem };
                          rememberRetest(driftId, payload?.retest_request ?? retest);
                          return payload;
                        }, 'Retest completed from verdict evidence.');
                      }}
                    >
                      Complete
                    </Button>
                  </>
                ) : null}
              </div>
            </div>
          );
        }
      }
    ];

    const planColumns: TableColumn<DataItem>[] = [
      { key: 'id', label: 'Plan', render: (item) => getString(item, ['id']) },
      { key: 'target', label: 'Target group', render: (item) => getString(item, ['target_group_id']) },
      { key: 'state', label: 'State', render: (item) => <Badge tone={getString(item, ['state']) === 'completed' ? 'success' : 'warn'}>{formatSnakeLabel(getString(item, ['state']))}</Badge> },
      {
        key: 'scenarios',
        label: 'Scenarios',
        render: (item) => (
          Array.isArray(item.scenarios)
            ? (item.scenarios as string[]).map((scenario) => VALIDATION_SCENARIO_LABELS[scenario] ?? formatSnakeLabel(scenario)).join(', ')
            : '—'
        )
      },
      {
        key: 'actions',
        label: 'Actions',
        render: (item) => {
          const id = getString(item, ['id'], '');
          const state = getString(item, ['state'], '');
          return (
            <div className="row-actions">
              {!['completed', 'cancelled'].includes(state) ? (
                <Button size="sm" variant="secondary" loading={busy === `plan-exec-${id}`} disabled={busy !== ''} onClick={() => {
                  if (!window.confirm('Execute this WAF validation plan now?')) return;
                  void handleAction(`plan-exec-${id}`, () => requestJson(config, session, `/v1/waf/validation-plans/${id}/execute`, { method: 'POST' }), 'Validation plan execute tick completed.');
                }}>Execute</Button>
              ) : null}
              {!['completed', 'cancelled'].includes(state) ? (
                <Button size="sm" variant="ghost" loading={busy === `plan-cancel-${id}`} disabled={busy !== ''} onClick={() => {
                  if (!window.confirm('Cancel this validation plan?')) return;
                  void handleAction(`plan-cancel-${id}`, () => requestJson(config, session, `/v1/waf/validation-plans/${id}/cancel`, { method: 'POST' }), 'Validation plan cancelled.');
                }}>Cancel</Button>
              ) : null}
            </div>
          );
        }
      }
    ];

    const exceptionColumns: TableColumn<DataItem>[] = [
      { key: 'asset', label: 'Asset', render: (item) => getString(item, ['waf_asset_id', 'asset_id']) },
      { key: 'owner', label: 'Owner', render: (item) => getString(item, ['owner']) },
      { key: 'reason', label: 'Reason', render: (item) => getString(item, ['reason']) },
      { key: 'expires', label: 'Expires', render: (item) => formatDate(item.expires_at) }
    ];

    const opsSections: Array<{ id: string; title: string; description: string; body: ReactNode }> = [
      {
        id: 'driftScan',
        title: 'Drift scan',
        description: 'Metadata-only posture drift comparison from scheduled or on-demand scans.',
        body: (
          <div className="product-form">
            {driftScanLatestLoading ? (
              <div className="kv-list" aria-busy="true" aria-label="Loading latest drift scan">
                <div><span className="muted">Latest scan</span><span className="skeleton skeleton-text" /></div>
                <div><span className="muted">Events opened</span><span className="skeleton skeleton-text" /></div>
              </div>
            ) : null}
            {driftScanLatestError ? (
              <div className="form-banner error">
                {driftScanLatestError}
                <Button size="sm" variant="ghost" type="button" onClick={() => setDriftLatestRetryToken((n) => n + 1)}>Retry</Button>
              </div>
            ) : null}
            {!driftScanLatestLoading ? (
              <div className="kv-list">
                <div><span>Latest scan</span><strong>{driftScanLatest ? formatDate(driftScanLatest.completed_at ?? driftScanLatest.created_at) : driftScanLatestError ? 'Failed to load' : 'None yet'}</strong></div>
                <div><span>Events opened</span><strong>{getString(driftScanLatest ?? {}, ['events_opened'], String(getNumber(driftScanLatest ?? {}, ['drift_events_created'])))}</strong></div>
              </div>
            ) : null}
            <div className="form-actions">
              <Button
                disabled={busy !== ''}
                onClick={() => {
                  if (!window.confirm('Run a drift scan now?')) return;
                  void handleAction('drift-scan-run', async () => {
                    const payload = await requestJson(config, session, '/v1/waf/drift-scans/run', { method: 'POST' }) as { scan_result?: DataItem };
                    if (payload?.scan_result) setDriftScanLatest(payload.scan_result);
                    setDriftScanLatestError('');
                    return payload;
                  }, 'Drift scan completed.');
                }}
              >
                Run drift scan
              </Button>
            </div>
          </div>
        )
      },
      {
        id: 'driftEvents',
        title: 'Drift events',
        description: 'Workflow status and safe retest controls for posture drift events.',
        body: (
          <DataTable
            columns={driftColumns}
            items={data.wafDriftEvents}
            empty={<EmptyState icon={TriangleAlert} title="No drift events." body="Drift events appear after posture weakens or drift scans detect changes." />}
          />
        )
      },
      {
        id: 'validationPlans',
        title: 'Validation plans (operator)',
        description: 'Safe orchestrator validation plans; production scheduling may still use your external runner.',
        body: (
          <div className="stack">
            <form className="product-form" onSubmit={(event: FormEvent<HTMLFormElement>) => {
              event.preventDefault();
              const formElement = event.currentTarget;
              const form = new FormData(formElement);
              const targetGroupId = String(form.get('target_group_id') ?? '').trim();
              if (!targetGroupId) {
                setError('Select a target group before creating a validation plan.');
                return;
              }
              const scenarios = VALIDATION_PLAN_SCENARIOS.filter((scenario) => form.get(`scenario_${scenario}`) === 'on');
              void handleAction('create-validation-plan', () => requestJson(config, session, '/v1/waf/validation-plans', {
                method: 'POST',
                body: {
                  target_group_id: targetGroupId,
                  mode: String(form.get('mode') ?? 'manual').trim(),
                  scenarios: scenarios.length > 0 ? scenarios : ['marker', 'fingerprint'],
                  max_concurrent: Number(form.get('max_concurrent') ?? 2)
                }
              }), 'Validation plan created.');
              formElement.reset();
            }}>
              <label><span>Target group</span>
                <select name="target_group_id" defaultValue="" required>
                  <option value="">Select target group</option>
                  {data.targetGroups.map((group) => <option key={getString(group, ['id'])} value={getString(group, ['id'])}>{getString(group, ['name', 'id'])}</option>)}
                </select>
              </label>
              <label><span>Mode</span>
                <select name="mode" defaultValue="manual"><option value="manual">manual</option><option value="on_demand">on_demand</option></select>
              </label>
              <label><span>Max concurrent</span><input name="max_concurrent" type="number" min="1" max="10" defaultValue="2" /></label>
              <div className="check-row full">
                {VALIDATION_PLAN_SCENARIOS.map((scenario) => (
                  <label key={scenario} className="check-row"><input name={`scenario_${scenario}`} type="checkbox" defaultChecked={scenario === 'marker' || scenario === 'fingerprint'} /><span>{VALIDATION_SCENARIO_LABELS[scenario] ?? formatSnakeLabel(scenario)}</span></label>
                ))}
              </div>
              <div className="form-actions full"><Button type="submit" disabled={busy !== '' || data.targetGroups.length === 0}>Create plan</Button></div>
            </form>
            <DataTable
              columns={planColumns}
              items={data.wafValidationPlans}
              empty={<EmptyState icon={ListChecks} title="No validation plans." body="Create a safe validation plan for a declared target group." />}
            />
          </div>
        )
      },
      {
        id: 'exceptions',
        title: 'Approved exceptions',
        description: 'Tenant-scoped approved exceptions that suppress findings until expiry.',
        body: (
          <div className="stack">
            <form className="product-form" onSubmit={(event: FormEvent<HTMLFormElement>) => {
              event.preventDefault();
              const formElement = event.currentTarget;
              const form = new FormData(formElement);
              const assetId = String(form.get('waf_asset_id') ?? exceptionAssetId).trim();
              if (!assetId) {
                setError('Select a WAF asset before creating an exception.');
                return;
              }
              if (!window.confirm('Create a WAF exception? It suppresses findings for the scope until expiry.')) return;
              void handleAction('create-waf-exception', () => requestJson(config, session, `/v1/waf/assets/${encodeURIComponent(assetId)}/exception`, {
                method: 'POST',
                body: {
                  owner: String(form.get('owner') ?? 'edge-team').trim(),
                  reason: String(form.get('reason') ?? 'approved_scope_exception').trim(),
                  expires_at: defaultExceptionExpiryIso()
                }
              }), 'WAF exception recorded.');
              formElement.reset();
            }}>
              <label><span>WAF asset</span>
                <select name="waf_asset_id" value={exceptionAssetId} onChange={(event) => setExceptionAssetId(event.target.value)} required>
                  <option value="">Select WAF asset</option>
                  {data.wafAssets.length === 0 ? <option value="" disabled>No assets declared</option> : null}
                  {data.wafAssets.map((asset) => {
                    const id = getString(asset, ['id'], '');
                    return <option key={id} value={id}>{getString(asset, ['canonical_url', 'display_ref', 'id'])}</option>;
                  })}
                </select>
              </label>
              <label><span>Owner</span><input name="owner" defaultValue="edge-team" required /></label>
              <label className="full"><span>Reason</span><input name="reason" defaultValue="approved_scope_exception" required /></label>
              <div className="form-actions full"><Button type="submit" disabled={busy !== '' || data.wafAssets.length === 0}>Create exception</Button></div>
            </form>
            <DataTable
              columns={exceptionColumns}
              items={data.wafExceptions}
              empty={<EmptyState icon={FileCheck2} title="No active exceptions." body="Approved exceptions appear here after asset-scoped exception creation." />}
            />
          </div>
        )
      }
    ];

    return (
      <div className="stack">
        {opsSections.map((section) => {
          const panelId = `waf-ops-${section.id}`;
          const expanded = Boolean(wafOpsSectionOpen[section.id]);
          return (
            <Card key={section.id} density="compact">
              <CardHeader>
                <CardTitle>{section.title}</CardTitle>
                <CardDescription>{section.description}</CardDescription>
              </CardHeader>
              <CardContent className="stack-tight">
                <Button
                  type="button"
                  variant="ghost"
                  className="disclosure-toggle"
                  aria-expanded={expanded}
                  aria-controls={panelId}
                  onClick={() => toggleWafOpsSection(section.id)}
                >
                  <ChevronDown size={16} className="disclosure-chevron" aria-hidden />
                  {expanded ? 'Collapse section' : 'Expand section'}
                </Button>
                {expanded ? <div id={panelId}>{section.body}</div> : null}
              </CardContent>
            </Card>
          );
        })}
      </div>
    );
  }

  function renderCreateForm() {
    if (route === 'waf-posture') {
      return (
        <form className="product-form" onSubmit={(event: FormEvent<HTMLFormElement>) => {
          event.preventDefault();
          const formElement = event.currentTarget;
          const form = new FormData(formElement);
          const targetGroupId = String(form.get('target_group_id') ?? wafAssetTargetGroupId).trim();
          const targetId = String(form.get('target_id') ?? '').trim();
          if (!targetGroupId) {
            setError('Select a declared target group before creating a WAF asset.');
            return;
          }
          if (!targetId) {
            setError('Select a target from the chosen group before creating a WAF asset.');
            return;
          }
          void handleAction('create-waf-asset', () => requestJson(config, session, '/v1/waf/assets', {
            method: 'POST',
            body: {
              target_group_id: targetGroupId,
              target_id: targetId,
              canonical_url: String(form.get('canonical_url') ?? '').trim(),
              owner_hint: String(form.get('owner_hint') ?? 'edge-team').trim()
            }
          }), 'WAF asset created.');
          formElement.reset();
        }}>
          <label><span>Target group</span>
            <select
              name="target_group_id"
              value={wafAssetTargetGroupId}
              disabled={data.targetGroups.length === 0}
              onChange={(event) => setWafAssetTargetGroupId(event.target.value)}
            >
              <option value="">Select target group</option>
              {data.targetGroups.length === 0 ? <option value="" disabled>No target groups declared</option> : null}
              {data.targetGroups.map((g) => <option key={getString(g, ['id'])} value={getString(g, ['id'])}>{getString(g, ['name', 'id'])}</option>)}
            </select>
          </label>
          {wafAssetTargetsError ? (
            <div className="form-banner error">
              {wafAssetTargetsError}
              <Button size="sm" variant="ghost" type="button" onClick={() => setWafTargetsRetryToken((n) => n + 1)}>Retry</Button>
            </div>
          ) : null}
          {wafAssetTargetsLoading ? <div className="skeleton skeleton-text" aria-busy="true" aria-label="Loading targets for selected group" /> : null}
          <label><span>Target</span>
            <select name="target_id" defaultValue="" disabled={wafAssetTargetsLoading || wafAssetTargets.length === 0} required>
              <option value="">{wafAssetTargetsLoading ? 'Loading targets…' : wafAssetTargets.length === 0 ? 'Add a target to the selected group' : 'Select target'}</option>
              {wafAssetTargets.map((target) => {
                const targetId = getString(target, ['id'], '');
                return <option key={targetId} value={targetId}>{getString(target, ['value', 'id'])} ({getString(target, ['kind'], 'target')})</option>;
              })}
            </select>
          </label>
          <label><span>Canonical URL</span><input name="canonical_url" placeholder="https://app.example.com" required /></label>
          {showMoreCreateOptions ? (
            <label><span>Owner hint</span><input name="owner_hint" defaultValue="edge-team" /></label>
          ) : null}
          <div className="form-actions full">
            <Button type="button" variant="ghost" aria-expanded={showMoreCreateOptions} onClick={() => setShowMoreCreateOptions((open) => !open)}>
              {showMoreCreateOptions ? 'Fewer options' : 'More options'}
            </Button>
            <Button type="submit" disabled={busy !== '' || data.targetGroups.length === 0 || wafAssetTargets.length === 0}>Create WAF asset</Button>
          </div>
        </form>
      );
    }
    if (route === 'cve-pipeline') {
      return (
        <form className="product-form" onSubmit={(event: FormEvent<HTMLFormElement>) => {
          event.preventDefault();
          const formElement = event.currentTarget;
          const form = new FormData(formElement);
          void handleAction('create-cve', () => requestJson(config, session, '/v1/waf/cve-pipeline', {
            method: 'POST',
            body: {
              cve_id: String(form.get('cve_id') ?? '').trim(),
              severity: String(form.get('severity') ?? 'high').trim(),
              affected_products: String(form.get('affected_products') ?? 'declared-service').trim().split(',').map((value) => value.trim()).filter(Boolean),
              known_exploited: form.get('known_exploited') === 'on'
            }
          }), 'CVE pipeline item created.');
          formElement.reset();
        }}>
          <label><span>CVE ID</span><input name="cve_id" placeholder="CVE-2026-0001" required /></label>
          <label><span>Affected products</span><input name="affected_products" defaultValue="declared-service" required /></label>
          <label><span>Severity</span>
            <select name="severity" defaultValue="high"><option value="critical">critical</option><option value="high">high</option><option value="medium">medium</option></select>
          </label>
          {showMoreCreateOptions ? (
            <label className="check-row full"><input name="known_exploited" type="checkbox" /><span>Known exploited (KEV)</span></label>
          ) : null}
          <div className="form-actions full">
            <Button type="button" variant="ghost" aria-expanded={showMoreCreateOptions} onClick={() => setShowMoreCreateOptions((open) => !open)}>
              {showMoreCreateOptions ? 'Fewer options' : 'More options'}
            </Button>
            <Button type="submit" loading={busy === 'create-cve'} disabled={busy !== ''}>Create CVE item</Button>
          </div>
        </form>
      );
    }
    if (route === 'supply-chain') {
      return (
        <form className="product-form" onSubmit={(event: FormEvent<HTMLFormElement>) => {
          event.preventDefault();
          const formElement = event.currentTarget;
          const form = new FormData(formElement);
          void handleAction('create-risk', () => requestJson(config, session, '/v1/waf/supply-chain/risks', {
            method: 'POST',
            body: {
              exposure_type: String(form.get('exposure_type') ?? 'dangling_cname').trim(),
              hostname: String(form.get('hostname') ?? '').trim(),
              severity: String(form.get('severity') ?? 'high').trim(),
              confidence: Number(form.get('confidence') ?? 0.8),
              state: 'suspected',
              evidence_summary: { data_source: 'customer_declared' },
              remediation_steps: ['Review DNS chain and remove dangling reference.']
            }
          }), 'Supply-chain risk created.');
          formElement.reset();
        }}>
          <label><span>Hostname</span><input name="hostname" placeholder="orphan.example.com" required /></label>
          <label><span>Exposure type</span>
            <select name="exposure_type" defaultValue="dangling_cname">
              {SUPPLY_CHAIN_EXPOSURE_TYPES.map((entry) => (
                <option key={entry.id} value={entry.id} title={entry.hint}>{entry.label}</option>
              ))}
            </select>
          </label>
          <p className="muted">Choose the exposure pattern that best matches the declared DNS or hostname risk.</p>
          <label><span>Severity</span><select name="severity" defaultValue="high"><option value="critical">critical</option><option value="high">high</option></select></label>
          {showMoreCreateOptions ? (
            <label><span>Confidence</span><input name="confidence" type="number" min="0" max="1" step="0.1" defaultValue="0.8" /></label>
          ) : (
            <input type="hidden" name="confidence" value="0.8" />
          )}
          <div className="form-actions full">
            <Button type="button" variant="ghost" aria-expanded={showMoreCreateOptions} onClick={() => setShowMoreCreateOptions((open) => !open)}>
              {showMoreCreateOptions ? 'Fewer options' : 'More options'}
            </Button>
            <Button type="submit" disabled={busy !== ''}>Create risk</Button>
          </div>
        </form>
      );
    }
    if (route === 'remediation') {
      return (
        <form className="product-form" onSubmit={(event: FormEvent<HTMLFormElement>) => {
          event.preventDefault();
          const formElement = event.currentTarget;
          const form = new FormData(formElement);
          const findingId = String(form.get('finding_id') ?? '').trim();
          if (!findingId) {
            setError('Select a finding before creating an action item.');
            return;
          }
          void handleAction('create-action-item', () => requestJson(config, session, '/v1/waf/action-items', {
            method: 'POST',
            body: { finding_id: findingId }
          }), 'Remediation action item created.');
          formElement.reset();
        }}>
          <label><span>Finding</span>
            <select name="finding_id" defaultValue="" required>
              <option value="">Select finding</option>
              {data.findings.length === 0 ? <option value="" disabled>No findings available</option> : null}
              {data.findings.map((finding) => {
                const id = getString(finding, ['id'], '');
                return <option key={id} value={id}>{getString(finding, ['title', 'id'])} ({getString(finding, ['severity'])})</option>;
              })}
            </select>
          </label>
          <div className="form-actions full"><Button type="submit" disabled={busy !== '' || data.findings.length === 0}>Create action item</Button></div>
        </form>
      );
    }
    if (route === 'discovery') {
      return (
        <form className="product-form" onSubmit={(event: FormEvent<HTMLFormElement>) => {
          event.preventDefault();
          const formElement = event.currentTarget;
          const form = new FormData(formElement);
          const rootDomain = String(form.get('root_domain') ?? '').trim().toLowerCase();
          const displayName = String(form.get('display_name') ?? '').trim();
          const entityId = String(form.get('entity_id') ?? '').trim() || `ent_${rootDomain.replace(/[^a-z0-9]+/g, '_').replace(/^_|_$/g, '') || 'declared'}`;
          if (!rootDomain) {
            setError('Enter a root domain before declaring an entity.');
            return;
          }
          void handleAction('create-entity', () => requestJson(config, session, '/v1/discovery/entities', {
            method: 'POST',
            body: {
              entity_id: entityId,
              entity_type: String(form.get('entity_type') ?? 'parent_organization').trim(),
              name: displayName || rootDomain,
              display_name: displayName || rootDomain,
              root_domains: [rootDomain],
              country: String(form.get('country') ?? 'US').trim(),
              confidence: Number(form.get('confidence') ?? 0.85),
              source: String(form.get('source') ?? 'customer_import').trim()
            }
          }), 'Discovery entity declared.');
          formElement.reset();
        }}>
          <label><span>Root domain</span><input name="root_domain" placeholder="example.com" required /></label>
          <label><span>Display name</span><input name="display_name" placeholder="Acme Corp" /></label>
          <label><span>Type</span>
            <select name="entity_type" defaultValue="parent_organization">
              <option value="parent_organization">parent organization</option>
              <option value="subsidiary">subsidiary</option>
              <option value="brand">brand</option>
              <option value="region">region</option>
            </select>
          </label>
          {showMoreCreateOptions ? (
            <>
              <label><span>Entity ID</span><input name="entity_id" placeholder="ent_acme (optional)" /></label>
              <label><span>Country</span><input name="country" defaultValue="US" /></label>
              <label><span>Confidence</span><input name="confidence" type="number" min="0" max="1" step="0.05" defaultValue="0.85" /></label>
              <label><span>Source</span><input name="source" defaultValue="customer_import" /></label>
            </>
          ) : (
            <>
              <input type="hidden" name="country" value="US" />
              <input type="hidden" name="confidence" value="0.85" />
              <input type="hidden" name="source" value="customer_import" />
            </>
          )}
          <div className="form-actions full">
            <Button type="button" variant="ghost" aria-expanded={showMoreCreateOptions} onClick={() => setShowMoreCreateOptions((open) => !open)}>
              {showMoreCreateOptions ? 'Fewer options' : 'More options'}
            </Button>
            <Button type="submit" disabled={busy !== ''}>Declare entity</Button>
          </div>
        </form>
      );
    }
    return null;
  }

  return (
    <div className="content">
      <PageHeader route={route} />
      {!enabled ? (
        <Card>
          <CardHeader>
            <CardTitle>{route === 'discovery' ? 'External discovery disabled' : route === 'cve-pipeline' ? 'CVE pipeline disabled' : 'WAF posture disabled'}</CardTitle>
            <CardDescription>Optional add-ons fail closed when their feature flag is off.</CardDescription>
          </CardHeader>
          <CardContent>
            <EmptyState
              icon={ShieldCheck}
              title={route === 'discovery' ? 'External discovery is not enabled' : route === 'cve-pipeline' ? 'CVE pipeline is not enabled' : 'WAF posture is not enabled'}
              body="Ask your administrator to enable this add-on for your tenant. No posture data is shown while the feature is off."
            />
          </CardContent>
        </Card>
      ) : (
        <>
          {(message || error) && <div className={error ? 'form-banner error' : 'form-banner'}>{error || message}</div>}
          {(route !== 'waf-posture' || wafPostureTab === 'overview' || wafPostureTab === 'assets') ? (
            <div className="metric-grid three">
              {tableConfig.metricCards.map((metric) => <MetricCard key={metric.label} {...metric} showStatusBadge={false} />)}
            </div>
          ) : null}
          {route === 'waf-posture' ? (
            <Tabs
              value={wafPostureTab}
              options={WAF_POSTURE_SURFACE_TABS.map((tab) => ({ id: tab.id, label: tab.label }))}
              onChange={setWafPostureTab}
              className="tabs-wrap"
            />
          ) : null}
          {route === 'remediation' ? (
            <Card>
              <CardHeader>
                <CardTitle>Remediation action items</CardTitle>
                <CardDescription>Workflow status for WAF findings converted into tracked remediation tasks.</CardDescription>
              </CardHeader>
              <CardContent className="stack-tight">
                <div className="page-toolbar">
                  <Button type="button" variant="secondary" aria-expanded={showRemediationCreateForm} onClick={() => setShowRemediationCreateForm((open) => !open)}>
                    {showRemediationCreateForm ? 'Hide create form' : 'Create action item'}
                  </Button>
                </div>
                {showRemediationCreateForm ? renderCreateForm() : null}
                <DataTable
                  columns={tableConfig.columns}
                  items={data.wafActionItems}
                  selectedId={selectedActionItemId || null}
                  getRowId={(item) => getString(item, ['action_item_id', 'id'], '')}
                  getRowProps={(item) => {
                    const id = getString(item, ['action_item_id', 'id'], '');
                    return {
                      onClick: () => setSelectedActionItemId(id),
                      onKeyDown: (event) => {
                        if (event.key === 'Enter' || event.key === ' ') {
                          event.preventDefault();
                          setSelectedActionItemId(id);
                        }
                      },
                      tabIndex: 0,
                      'aria-label': `Select remediation item ${getString(item, ['title', 'id'], id)}`
                    };
                  }}
                  empty={<EmptyState icon={ShieldCheck} title={tableConfig.emptyTitle} body={tableConfig.emptyBody} />}
                />
              </CardContent>
            </Card>
          ) : null}
          {route === 'cve-pipeline' ? (
            <Card>
              <CardHeader>
                <CardTitle>CVE pipeline</CardTitle>
                <CardDescription>Ingest and triage CVE records. Workflow mutations live on CVE detail.</CardDescription>
              </CardHeader>
              <CardContent className="stack-tight">
                <div className="page-toolbar">
                  <Button type="button" variant="secondary" aria-expanded={showCveIngestForm} onClick={() => setShowCveIngestForm((open) => !open)}>
                    {showCveIngestForm ? 'Hide ingest form' : 'Ingest CVE'}
                  </Button>
                </div>
                {showCveIngestForm ? renderCreateForm() : null}
                <div className="page-toolbar-labeled">
                  <Select
                    className="inline-select-control"
                    label="Severity"
                    value={cveFilterSeverity}
                    onChange={setCveFilterSeverity}
                    options={[
                      { value: 'all', label: 'All severities' },
                      { value: 'critical', label: 'Critical' },
                      { value: 'high', label: 'High' },
                      { value: 'medium', label: 'Medium' }
                    ]}
                  />
                  <Select
                    className="inline-select-control"
                    label="Stage"
                    value={cveFilterStage}
                    onChange={setCveFilterStage}
                    options={[
                      { value: 'all', label: 'All stages' },
                      ...[...new Set(data.cvePipeline.map((item) => getString(item, ['stage', 'status']).toLowerCase()).filter(Boolean))]
                        .map((stage) => ({ value: stage, label: formatSnakeLabel(stage) }))
                    ]}
                  />
                  <label className="check-row">
                    <input type="checkbox" checked={cveFilterKev} onChange={(event) => setCveFilterKev(event.target.checked)} />
                    <span>KEV only</span>
                  </label>
                </div>
                <DataTable columns={routeConfig['cve-pipeline'].columns} items={filteredCvePipeline} empty={<EmptyState icon={TriangleAlert} title={tableConfig.emptyTitle} body={tableConfig.emptyBody} />} />
              </CardContent>
            </Card>
          ) : null}
          {route === 'supply-chain' ? (
            <Card>
              <CardHeader><CardTitle>Supply-chain risks</CardTitle><CardDescription>Declared DNS and hostname exposure records with customer-approved remediation phases.</CardDescription></CardHeader>
              <CardContent className="stack-tight">
                <div className="page-toolbar-labeled">
                  <Button type="button" variant="secondary" aria-expanded={showSupplyChainCreateForm} onClick={() => setShowSupplyChainCreateForm((open) => !open)}>
                    {showSupplyChainCreateForm ? 'Hide create form' : 'Create supply-chain risk'}
                  </Button>
                  <Select
                    className="inline-select-control"
                    label="State"
                    value={supplyChainFilterState}
                    onChange={setSupplyChainFilterState}
                    options={[
                      { value: 'all', label: 'All states' },
                      ...[...new Set(data.supplyChainRisks.map((item) => getString(item, ['state']).toLowerCase()).filter(Boolean))]
                        .map((state) => ({ value: state, label: formatSupplyChainStateLabel(state) }))
                    ]}
                  />
                  <Select
                    className="inline-select-control"
                    label="Severity"
                    value={supplyChainFilterSeverity}
                    onChange={setSupplyChainFilterSeverity}
                    options={[
                      { value: 'all', label: 'All severities' },
                      { value: 'critical', label: 'Critical' },
                      { value: 'high', label: 'High' },
                      { value: 'medium', label: 'Medium' },
                      { value: 'low', label: 'Low' }
                    ]}
                  />
                </div>
                {showSupplyChainCreateForm ? renderCreateForm() : null}
                <DataTable columns={routeConfig['supply-chain'].columns} items={filteredSupplyChainRisks} empty={<EmptyState icon={ShieldCheck} title={tableConfig.emptyTitle} body={tableConfig.emptyBody} />} />
              </CardContent>
            </Card>
          ) : null}
          {route === 'discovery' ? (
            <Card>
              <CardHeader><CardTitle>Discovery queues</CardTitle><CardDescription>Review inbox items, candidates, and approved entities before expanding declared scope.</CardDescription></CardHeader>
              <CardContent className="stack-tight">
                <div className="page-toolbar">
                  <Button type="button" variant="secondary" aria-expanded={showDiscoveryDeclareForm} onClick={() => setShowDiscoveryDeclareForm((open) => !open)}>
                    {showDiscoveryDeclareForm ? 'Hide declare form' : 'Declare entity'}
                  </Button>
                </div>
                {showDiscoveryDeclareForm ? renderCreateForm() : null}
                <Tabs
                  value={discoveryQueueTab}
                  options={[
                    { id: 'inbox', label: 'Inbox', count: data.discoveryInbox.length },
                    { id: 'candidates', label: 'Candidates', count: data.discoveryCandidates.length },
                    { id: 'entities', label: 'Entities', count: data.discoveryEntities.length }
                  ]}
                  onChange={(value) => setDiscoveryQueueTab(value as 'inbox' | 'candidates' | 'entities')}
                  className="tabs-wrap"
                />
                <DataTable columns={discoveryQueueColumns} items={discoveryQueueItems} empty={<EmptyState icon={ShieldCheck} title={tableConfig.emptyTitle} body={tableConfig.emptyBody} />} />
              </CardContent>
            </Card>
          ) : null}

          {route === 'waf-posture' && wafPostureTab === 'overview' ? (
            <Card>
              <CardHeader>
                <CardTitle>Declare WAF asset</CardTitle>
                <CardDescription>Link a declared target to your WAF posture scope when you are ready to expand coverage.</CardDescription>
              </CardHeader>
              <CardContent className="stack">
                <div className="form-actions">
                  <Button
                    type="button"
                    disabled={busy !== ''}
                    aria-expanded={showWafDeclareAssetForm}
                    onClick={() => setShowWafDeclareAssetForm((open) => !open)}
                  >
                    {showWafDeclareAssetForm ? 'Hide declare form' : 'Declare WAF asset'}
                  </Button>
                  <Button type="button" variant="ghost" onClick={() => setWafPostureTab('assets')}>
                    View declared assets
                  </Button>
                </div>
                {showWafDeclareAssetForm ? renderCreateForm() : null}
              </CardContent>
            </Card>
          ) : null}
          {route === 'remediation' ? (
            <Card id="remediation-delivery-card">
              <CardHeader>
                <CardTitle>Connector delivery preview</CardTitle>
                <CardDescription>Preview remediation delivery to your connector without sending production traffic.</CardDescription>
              </CardHeader>
              <CardContent className="stack-tight">
                <Button type="button" variant="ghost" aria-expanded={showRemediationDeliverPanel} onClick={() => setShowRemediationDeliverPanel((open) => !open)}>
                  {showRemediationDeliverPanel ? 'Hide delivery panel' : selectedActionItemId ? 'Delivery panel (item selected)' : 'Show delivery panel'}
                </Button>
                {showRemediationDeliverPanel ? (
                  <div className="product-form">
                    <Select
                      className="inline-select-control"
                      label="Action item"
                      value={selectedActionItemId}
                      onChange={setSelectedActionItemId}
                      options={[
                        { value: '', label: 'Select action item' },
                        ...data.wafActionItems.map((item) => {
                          const id = getString(item, ['action_item_id', 'id'], '');
                          return { value: id, label: getString(item, ['title', 'id']) };
                        })
                      ]}
                    />
                    <Select
                      className="inline-select-control"
                      label="Channel / connector"
                      value={deliverChannel}
                      onChange={setDeliverChannel}
                      options={REMEDIATION_CHANNELS.map((channel) => ({
                        value: channel,
                        label: REMEDIATION_CHANNEL_LABELS[channel] ?? channel
                      }))}
                    />
                    <div className="form-actions full">
                      <Button
                        loading={Boolean(selectedActionItemId && busy === `deliver-${selectedActionItemId}`)}
                        disabled={busy !== '' || data.wafActionItems.length === 0}
                        onClick={() => {
                          const actionItemId = selectedActionItemId;
                          if (!actionItemId) {
                            setError('Select an action item before delivering.');
                            return;
                          }
                          const channelLabel = REMEDIATION_CHANNEL_LABELS[deliverChannel] ?? deliverChannel;
                          if (!window.confirm(`Deliver this action item via ${channelLabel}? (Dry-run preview.)`)) return;
                          void handleAction(`deliver-${actionItemId}`, () => requestJson(config, session, `/v1/waf/action-items/${actionItemId}/deliver`, {
                            method: 'POST',
                            body: { channel: deliverChannel, connector: deliverChannel, dry_run: true }
                          }), 'Dry-run deliver preview generated.');
                        }}
                      >
                        Dry-run deliver
                      </Button>
                    </div>
                  </div>
                ) : null}
              </CardContent>
            </Card>
          ) : null}
          {route === 'waf-posture' && wafPostureTab === 'overview' ? (
            <Card>
              <CardHeader><CardTitle>Coverage summary</CardTitle><CardDescription>Protected, underprotected, and unknown asset counts across declared WAF scope.</CardDescription></CardHeader>
              <CardContent className="factor-list">
                {['protected', 'underprotected', 'unprotected', 'unknown', 'excluded'].map((status) => {
                  const count = getNumber(data.wafCoverage ?? {}, [status]);
                  const percent = getNestedNumber(data.wafCoverage, ['percentages', status], 0);
                  return (
                    <div className="factor" key={status}>
                      <div><strong title={coverageStatusHint(status)}>{formatCoverageStatusLabel(status)}</strong><span>{count} assets</span></div>
                      <Badge tone={coverageBucketBadgeTone(status, count, percent)}>{Math.round(percent)}%</Badge>
                      <Progress value={percent} tone={coverageProgressTone(status, percent)} />
                    </div>
                  );
                })}
              </CardContent>
            </Card>
          ) : null}
          {route === 'waf-posture' && wafPostureTab === 'operations' ? renderWafOperatorPanels() : null}
          {route === 'waf-posture' && wafPostureTab === 'roadmap' ? renderWafRoadmapPanel() : null}
          {route === 'waf-posture' && wafPostureTab === 'assets' ? (
            <Card>
              <CardHeader>
                <CardTitle>Declared assets</CardTitle>
                <CardDescription>Per-asset pass rate uses finalized validations in the last 30 days. Rule health appears when connector snapshots are available.</CardDescription>
              </CardHeader>
              <CardContent>
                <DataTable
                  columns={wafAssetColumns}
                  items={data.wafAssets}
                  empty={<EmptyState icon={ShieldCheck} title="No WAF assets recorded." body="Create a declared WAF asset or import from an approved connector snapshot." />}
                />
              </CardContent>
            </Card>
          ) : null}
          {route === 'waf-posture' && wafPostureTab === 'overview' && data.wafAssets.length > 0 ? (
            <Card>
              <CardHeader>
                <CardTitle>Recent declared assets</CardTitle>
                <CardDescription>Showing up to three assets. Open the Assets tab for pass rate and rule health.</CardDescription>
              </CardHeader>
              <CardContent className="stack-tight">
                <DataTable columns={wafAssetColumns} items={data.wafAssets.slice(0, 3)} empty={null} />
                {data.wafAssets.length > 3 ? (
                  <div className="form-actions">
                    <Button type="button" variant="ghost" onClick={() => setWafPostureTab('assets')}>View all {data.wafAssets.length} assets</Button>
                  </div>
                ) : null}
              </CardContent>
            </Card>
          ) : null}
          {output ? (
            <Card>
              <CardHeader><CardTitle>Action result</CardTitle></CardHeader>
              <CardContent>
                <p className="muted">{message || 'Action completed successfully.'}</p>
                <Button variant="ghost" size="sm" type="button" aria-expanded={showTechnicalActionResult} onClick={() => setShowTechnicalActionResult((open) => !open)}>
                  {showTechnicalActionResult ? 'Hide technical details' : 'View technical details'}
                </Button>
                {showTechnicalActionResult ? <pre className="codeblock">{output}</pre> : null}
              </CardContent>
            </Card>
          ) : null}
        </>
      )}
    </div>
  );
}
