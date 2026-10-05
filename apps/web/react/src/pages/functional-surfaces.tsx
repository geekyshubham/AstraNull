import { useEffect, useMemo, useState, type FormEvent, type HTMLAttributes, type ReactNode } from 'react';
import {
  Activity,
  ListChecks,
  Search
} from 'lucide-react';
import { Badge } from '../components/ui/badge';
import { AnchorButton, Button } from '../components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../components/ui/card';
import { EmptyState } from '../components/ui/empty-state';
import { Progress } from '../components/ui/progress';
import { Select } from '../components/ui/select';
import { DataTable, type TableColumn } from '../components/ui/table';
import { Tabs } from '../components/ui/tabs';
import { FindingsListView } from '../components/findings/findings-list';
import { RunsPageHeadActions, RunsSocGatePanel } from '../components/runs/runs-soc-gate';
import { ValidationScanLauncher, type ScanLauncherMode } from '../components/runs/validation-scan-launcher';
import { ValidationScansTable } from '../components/runs/validation-scans-table';
import { canStartRun } from '../lib/run-permissions.mjs';
import { SCAN_STATUSES, isScanActive, scanDisplayName, scanStatusLabel } from '../lib/validation-scan.mjs';
import { ConfirmModal, formatMutationSuccessMessage, renderFriendlyEmptyState, useConfirmModal } from '../lib/crud-ui';
import { apiErrorMessage } from '../lib/error-messages';
import { buildEvidenceCustodyManifest } from '../lib/custody';
import { buildEvidenceChainExport, summarizeEvidenceExport } from '../lib/evidence-export';
import { hasEvidenceBackedVerdict } from '../lib/run-verdict';
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
  CHECK_SAFETY_SCOPE_TABS,
  countChecksBySafetyScope,
  filterChecksCatalog,
  type CheckFamilyTabId,
  type CheckSafetyScopeId
} from '../lib/checks-helpers';

import { requestJson } from '../lib/api';

import { routeTabs } from '../lib/prototype-manifest';
import { buildDetailHref } from '../lib/route-params';
import type { DataItem, PortalConfig, PortalData, PortalDataset, RouteId, Session } from '../lib/types';
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
import { cn, formatDate, formatRunDuration, pluralize, scoreTone } from '../lib/utils';
import { useTransitionKey } from '../lib/motion';
import { runStatusTone as runStatusBadgeTone } from '../lib/status-tone';
import type { ProgressTone } from '../components/ui/progress';
import { MetricCard, PageContextSummary, PageHeader } from './page-components';
import { useDesignVariant } from '../lib/design-variant';
import { VariantSwitch } from '../components/ui/variant-switch';
import { RunsRefined, type RunsRefinedProps } from './refined/runs-refined';
import { FindingsRefined, type FindingsRefinedProps } from './refined/findings-refined';
import { RoleRestrictedCard } from '../components/ui/role-restricted';
import { sessionHasPermission } from '../lib/dataset-access.mjs';
// @ts-ignore Plain ESM keeps executive labels directly testable with node:test.
import { plainCheckName, plainVerdictLabel } from '../lib/plain-language.mjs';

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
  l7: 'Application layer',
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
  if (safetyClass === 'soc_gated') return 'Governed request-only';
  return safetyClass.replace(/_/g, ' ');
}

function getRunVerdictValue(run: DataItem) {
  const verdict = run.verdict;
  if (verdict && typeof verdict === 'object' && !Array.isArray(verdict)) {
    const nested = getString(verdict as DataItem, ['verdict'], '');
    if (nested) return nested;
  }
  return getString(run, ['verdict', 'verdict'], '');
}

function buildLatestCheckVerdictMap(runs: DataItem[]) {
  const map = new Map<string, { verdict: string; runId: string }>();
  const sortKeys = new Map<string, string>();
  for (const run of runs) {
    const checkId = getString(run, ['check_id'], '');
    if (!checkId) continue;
    const status = getString(run, ['status'], '');
    if (!['completed', 'verdicted'].includes(status)) continue;
    const verdict = getRunVerdictValue(run);
    if (!verdict) continue;
    const at = String(run.updated_at ?? run.completed_at ?? run.started_at ?? run.created_at ?? '');
    const prevAt = sortKeys.get(checkId) ?? '';
    if (!prevAt || at.localeCompare(prevAt) >= 0) {
      sortKeys.set(checkId, at);
      map.set(checkId, { verdict, runId: getString(run, ['id'], '') });
    }
  }
  return map;
}

function formatCheckModeLabel(safetyClass: string) {
  if (safetyClass === 'safe') return 'safe';
  if (safetyClass === 'soc_gated') return 'governed';
  return formatSafetyClassLabel(safetyClass);
}

function checkModeBadgeTone(safetyClass: string): BadgeTone {
  if (safetyClass === 'safe') return 'success';
  if (safetyClass === 'soc_gated') return 'info';
  return 'muted';
}

function formatCheckBoundLabel(check: DataItem) {
  const maxRate = check.max_rate;
  if (typeof maxRate === 'number' && Number.isFinite(maxRate) && maxRate > 0) {
    return `${maxRate} RPS`;
  }
  if (typeof maxRate === 'string' && maxRate.trim()) {
    return maxRate.replace(/_/g, ' ');
  }
  const kind = getNestedString(check, ['probe_profile', 'kind'], '');
  if (kind === 'metadata_marker' || kind === 'ops_readiness') return 'metadata';
  const profile = check.probe_profile;
  if (profile && typeof profile === 'object' && !Array.isArray(profile)) {
    const maxRequests = Number((profile as DataItem).max_requests);
    if (Number.isFinite(maxRequests) && maxRequests === 1) return 'metadata';
  }
  return '—';
}

function catalogVerdictBadgeTone(verdict: string): BadgeTone {
  const key = verdict.trim().toLowerCase();
  if (['pass', 'passed', 'protected', 'ready', 'success', 'ok'].includes(key)) return 'success';
  if (['gap', 'fail', 'failed', 'unprotected', 'bypassable', 'penetrated', 'edge_exposed'].includes(key)) return 'danger';
  if (['review', 'partial', 'inconclusive', 'warn', 'warning', 'medium'].includes(key)) return 'warn';
  if (key === 'request') return 'muted';
  return verdictBadgeTone(verdict);
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



type BadgeTone = 'default' | 'success' | 'warn' | 'danger' | 'info' | 'muted';

function verdictBadgeTone(verdict: string): BadgeTone {
  const normalized = verdict.toLowerCase();
  if (normalized === 'pass' || normalized === 'ready') return 'success';
  if (normalized === 'fail' || normalized === 'failed') return 'danger';
  if (normalized === 'partial' || normalized === 'inconclusive') return 'warn';
  if (normalized === 'pending' || normalized === '—' || !normalized) return 'muted';
  return 'info';
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
  if (normalized === 'edge_protected') return 'info';
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

function runDisplayLabelForId(checks: DataItem[], runs: DataItem[], runId: string) {
  if (!runId) return '—';
  const run = runs.find((entry) => getString(entry, ['id']) === runId);
  if (!run) return runId;
  const titled = getString(run, ['name', 'title'], '');
  if (titled) return titled;
  return checkDisplayName(checks, getString(run, ['check_id']));
}

function resolveTargetGroupName(groups: DataItem[], groupId: string) {
  if (!groupId) return '—';
  const group = groups.find((item) => getString(item, ['id'], '') === groupId);
  return getString(group ?? {}, ['name', 'title'], groupId);
}

const IN_PROGRESS_RUN_STATUSES = new Set(['running', 'collecting']);

function isInProgressRunStatus(status: string) {
  return IN_PROGRESS_RUN_STATUSES.has(status);
}

/** Mirrors CANCELLABLE_STATUSES in src/services/testRuns.mjs and the run-detail action gate. */
const CANCELLABLE_RUN_STATUSES = new Set(['planned', 'running', 'collecting']);

function isCancellableRunStatus(status: string) {
  return CANCELLABLE_RUN_STATUSES.has(status);
}

function formatStartedAgo(value: unknown) {
  const started = Date.parse(String(value ?? ''));
  if (!Number.isFinite(started)) return '';
  const diffMs = Date.now() - started;
  if (diffMs < 0) return 'started just now';
  const seconds = Math.floor(diffMs / 1000);
  if (seconds < 60) return `started ${seconds}s ago`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `started ${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `started ${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `started ${days}d ago`;
}

// Scoped runtime style (guarded, tokens only) — mirrors the ui/* primitive pattern
// (see components/ui/badge.tsx / button.tsx). Provides the in-progress live-pulse dot
// with prefers-reduced-motion support. Does NOT modify the shared stylesheet.
const FUNCTIONAL_SURFACE_STYLE_ID = 'astranull-functional-surface-styles';

function ensureFunctionalSurfaceStyles() {
  if (typeof document === 'undefined') return;
  if (document.getElementById(FUNCTIONAL_SURFACE_STYLE_ID)) return;
  const node = document.createElement('style');
  node.id = FUNCTIONAL_SURFACE_STYLE_ID;
  node.textContent = `
.run-live-dot {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  background: var(--info);
  flex: none;
  animation: astranull-run-live-pulse 1.5s ease-in-out infinite;
}
@keyframes astranull-run-live-pulse {
  0%, 100% { opacity: 1; transform: scale(1); }
  50% { opacity: 0.35; transform: scale(0.7); }
}
@media (prefers-reduced-motion: reduce) {
  .run-live-dot { animation: none; opacity: 0.85; }
}
.catalog-filter-grid { display: grid; grid-template-columns: minmax(220px, 1.5fr) repeat(3, minmax(160px, 1fr)); gap: var(--space-3); align-items: end; }
.catalog-search-control { display: flex; min-height: 44px; align-items: center; gap: var(--space-2); border: 1px solid var(--border); border-radius: var(--radius-pill); background: var(--surface-sunk); padding: 0 var(--space-3); }
.catalog-search-control input { width: 100%; min-width: 0; border: 0; outline: 0; background: transparent; color: var(--fg); }
.catalog-check-primary, .catalog-cell-stack { display: flex; min-width: 0; flex-direction: column; gap: 3px; }
.catalog-check-primary strong { color: var(--fg); }
.catalog-check-primary small, .catalog-cell-stack small { color: var(--fg-2); font-size: var(--text-xs); }
.validation-catalog-table .data-table { min-width: 1040px; }
.validation-runs-table .data-table { min-width: 1180px; }
@media (max-width: 900px) { .catalog-filter-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); } .catalog-search-field { grid-column: 1 / -1; } }
@media (max-width: 620px) { .catalog-filter-grid { grid-template-columns: minmax(0, 1fr); } .catalog-search-field { grid-column: auto; } }
`;
  document.head.appendChild(node);
}

// Buckets a catalog check into a coarse verdict-status key for the checks status filter.
function checkStatusFilterKey(
  check: DataItem,
  verdicts: Map<string, { verdict: string; runId: string }>
) {
  const checkId = getString(check, ['check_id'], '');
  const latest = verdicts.get(checkId);
  if (latest?.verdict) {
    const key = latest.verdict.trim().toLowerCase();
    if (['pass', 'passed', 'protected', 'ready', 'success', 'ok'].includes(key)) return 'pass';
    if (['gap', 'fail', 'failed', 'unprotected', 'bypassable', 'penetrated', 'edge_exposed'].includes(key)) return 'gap';
    if (key === 'request') return 'request';
    return 'review';
  }
  if (getString(check, ['safety_class'], '') === 'soc_gated') return 'request';
  return 'untested';
}

const CHECK_FAMILY_FILTER_OPTIONS: { value: CheckFamilyTabId; label: string }[] = [
  { value: 'all', label: 'All families' },
  { value: 'recommended', label: 'Recommended' },
  { value: 'origin-bypass', label: 'Origin bypass' },
  { value: 'l3l4', label: 'L3 / L4' },
  { value: 'dns', label: 'DNS' },
  { value: 'l7api', label: 'Application layer' },
  { value: 'protocols', label: 'Protocols / TLS' },
  { value: 'reflection-amplification', label: 'Reflection / amplification' },
  { value: 'exploit', label: 'Exploit-based DoS' },
  { value: 'delivery-pattern', label: 'Delivery patterns' },
  { value: 'operations', label: 'Operations' },
  { value: 'high-scale', label: 'High-scale (governed)' }
];

const CHECK_STATUS_FILTER_OPTIONS = [
  { value: 'all', label: 'All statuses' },
  { value: 'pass', label: 'Pass' },
  { value: 'gap', label: 'Gap' },
  { value: 'review', label: 'Review' },
  { value: 'request', label: 'Governed request' },
  { value: 'untested', label: 'Untested' }
];

const TOKEN_EXPIRY_OPTIONS = [
  { value: '15', label: '15 minutes' },
  { value: '60', label: '1 hour' },
  { value: '240', label: '4 hours' },
  { value: '1440', label: '24 hours' }
];

const MASKED_TOKEN_SECRET = '\u2022'.repeat(32);

function TableSkeleton({ rows = 4, label = 'Loading' }: { rows?: number; label?: string }) {
  return (
    <div className="stack-tight" aria-busy="true" aria-label={label}>
      {Array.from({ length: rows }, (_, index) => (
        <div key={index} className="skeleton skeleton-row" />
      ))}
    </div>
  );
}

function MutationFeedbackBanner({
  message,
  error,
  neutral = false
}: {
  message: string;
  error: string;
  neutral?: boolean;
}) {
  if (!message && !error) return null;
  const className = error ? 'form-banner error' : neutral ? 'form-banner neutral' : 'form-banner';
  return (
    <div className={className} role={error ? 'alert' : 'status'} aria-live="polite">
      {error || message}
    </div>
  );
}

function FilterFieldset({ legend, children }: { legend: string; children: ReactNode }) {
  return (
    <fieldset className="filter-fieldset">
      <legend>{legend}</legend>
      {children}
    </fieldset>
  );
}

type SurfaceTableCardProps<T> = {
  title: string;
  description: ReactNode;
  columns: TableColumn<T>[];
  items: T[];
  empty: ReactNode;
  loading?: boolean;
  loadingLabel?: string;
  loadingRows?: number;
  contentClassName?: string;
  loadError?: string | null;
  onRetry?: () => void;
  getRowProps?: (item: T, index: number) => Omit<HTMLAttributes<HTMLTableRowElement>, 'key'>;
  getRowId?: (item: T, index: number) => string | number;
};

function SurfaceTableCard<T>({
  title,
  description,
  columns,
  items,
  empty,
  loading = false,
  loadingLabel = 'Loading table',
  loadingRows = 3,
  contentClassName,
  loadError,
  onRetry,
  getRowProps,
  getRowId
}: SurfaceTableCardProps<T>) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>{title}</CardTitle>
        <CardDescription>{description}</CardDescription>
      </CardHeader>
      <CardContent className={contentClassName} aria-busy={loading || undefined}>
        {loading ? (
          <TableSkeleton rows={loadingRows} label={loadingLabel} />
        ) : (
          <DataTable
            columns={columns}
            items={items}
            empty={empty}
            loadError={loadError}
            onRetry={onRetry}
            getRowProps={getRowProps}
            getRowId={getRowId}
          />
        )}
      </CardContent>
    </Card>
  );
}

function isInteractiveTableTarget(target: EventTarget | null) {
  return Boolean(target && (target as HTMLElement).closest('a, button'));
}

function buildDetailHashRowProps(
  detailRoute: string,
  id: string,
  ariaLabel: string
): Omit<HTMLAttributes<HTMLTableRowElement>, 'key'> {
  if (!id) return {};
  const hash = `${detailRoute}?id=${encodeURIComponent(id)}`;
  return {
    tabIndex: 0,
    style: { cursor: 'pointer' },
    'aria-label': ariaLabel,
    onClick: (event) => {
      if (isInteractiveTableTarget(event.target)) return;
      window.location.hash = hash;
    },
    onKeyDown: (event) => {
      if (event.key !== 'Enter' && event.key !== ' ') return;
      if (isInteractiveTableTarget(event.target)) return;
      event.preventDefault();
      window.location.hash = hash;
    }
  };
}

function formatCoverageStatusLabel(status: string) {
  const labels: Record<string, string> = {
    protected: 'Protected',
    edge_protected: 'Edge protected · not internally validated',
    underprotected: 'Underprotected',
    unprotected: 'Unprotected',
    unknown: 'Unknown',
    excluded: 'Excluded'
  };
  return labels[status] ?? status.replace(/_/g, ' ');
}

function coverageBucketBadgeTone(status: string, count: number, percent: number): BadgeTone {
  if (status === 'protected') return scoreTone(percent);
  if (status === 'edge_protected') return count > 0 ? 'info' : 'muted';
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
    edge_protected: 'Blocking was observed at the edge, but no matching internal or origin observation validates full protection.',
    underprotected: 'Partial coverage or weak rule effectiveness.',
    unprotected: 'No effective WAF coverage on declared scope.',
    unknown: 'Insufficient evidence to classify coverage.',
    excluded: 'Out of scope for WAF posture scoring.'
  };
  return hints[status] ?? '';
}

function checkDisplayName(checks: DataItem[], checkId: string, runId = '') {
  const check = checks.find((entry) => getString(entry, ['check_id']) === checkId);
  const name = getString(check ?? {}, ['name'], checkId);
  return plainCheckName(name || runId || 'View run');
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
    setError(apiErrorMessage(err, 'Action failed.'));
    return null;
  } finally {
    setBusy('');
  }
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
  onRefresh: (datasets?: readonly PortalDataset[]) => Promise<void>;
}) {
  const { confirm } = useConfirmModal();
  // Both hooks run unconditionally (rules of hooks); each page keeps its own preference.
  const [runsVariant, setRunsVariant] = useDesignVariant('runs');
  const [findingsVariant, setFindingsVariant] = useDesignVariant('findings');
  const [busy, setBusy] = useState('');
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');
  const [checkFilter, setCheckFilter] = useState<CheckFamilyTabId>('recommended');
  const [checkQuery, setCheckQuery] = useState('');
  const [checkSafetyScope, setCheckSafetyScope] = useState<CheckSafetyScopeId>('all');
  const [checkStatusFilter, setCheckStatusFilter] = useState('all');
  const [findingTab, setFindingTab] = useState<FindingTabId>('open');
  const [exportOutput, setExportOutput] = useState('');
  const [showTechnicalExport, setShowTechnicalExport] = useState(false);
  const [showFullEvidenceChain, setShowFullEvidenceChain] = useState(false);
  const [evidenceCustodyPreview, setEvidenceCustodyPreview] = useState<DataItem | null>(null);
  const [showEvidenceExportCenter, setShowEvidenceExportCenter] = useState(() => data.evidence.length > 0);
  const [exportPartialMissCount, setExportPartialMissCount] = useState(0);
  const [clipboardNotice, setClipboardNotice] = useState('');
  const [runStatusFilter, setRunStatusFilter] = useState('all');
  const [showSocRequestForm, setShowSocRequestForm] = useState(false);
  const [cancelRunId, setCancelRunId] = useState('');
  const [finalizeRunId, setFinalizeRunId] = useState('');
  const [scanLauncher, setScanLauncher] = useState<{ mode: ScanLauncherMode; scan: DataItem | null } | null>(null);
  const [scanStatusFilter, setScanStatusFilter] = useState('all');
  const evidenceChainCap = 12;

  const inFlightRuns = data.runs.filter((run) => isCancellableRunStatus(getString(run, ['status'], '')));
  const activeScans = data.validationScans.filter((scan) => isScanActive(scan));
  const canManageScans = canStartRun(session.role);
  const canRequestHighScale = sessionHasPermission(session, 'high_scale:request');

  const checkSafetyCounts = useMemo(() => countChecksBySafetyScope(data.checks), [data.checks]);
  const filteredChecks = useMemo(
    () => filterChecksCatalog(data.checks, checkFilter, checkSafetyScope),
    [data.checks, checkFilter, checkSafetyScope]
  );
  const latestCheckVerdicts = useMemo(() => buildLatestCheckVerdictMap(data.runs), [data.runs]);

  const visibleChecks = useMemo(() => {
    const needle = checkQuery.trim().toLowerCase();
    return filteredChecks.filter((check) => {
      if (checkStatusFilter !== 'all' && checkStatusFilterKey(check, latestCheckVerdicts) !== checkStatusFilter) return false;
      if (!needle) return true;
      return [
        getString(check, ['check_id'], ''),
        getString(check, ['name', 'title'], ''),
        getString(check, ['description', 'summary'], ''),
        getString(check, ['vector_family'], ''),
        getString(check, ['evidence_tier'], '')
      ].join(' ').toLowerCase().includes(needle);
    });
  }, [filteredChecks, checkQuery, checkStatusFilter, latestCheckVerdicts]);

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
    if (data.evidence.length > 0) setShowEvidenceExportCenter(true);
  }, [data.evidence.length]);

  useEffect(() => {
    if (route !== 'runs' || (inFlightRuns.length === 0 && activeScans.length === 0)) return undefined;
    const timer = window.setInterval(() => {
      void onRefresh(['runs', 'state', 'validationScans']);
    }, 8000);
    return () => window.clearInterval(timer);
  }, [route, inFlightRuns.length, activeScans.length, onRefresh]);

  async function cancelRun(id: string) {
    if (!id) return;
    setCancelRunId(id);
  }

  async function confirmCancelRun() {
    if (!canManageScans) return;
    const id = cancelRunId;
    if (!id) return;
    setBusy(`cancel-${id}`);
    setError('');
    setMessage('');
    try {
      const result = await requestJson(config, session, `/v1/test-runs/${id}/cancel`, { method: 'POST' });
      setMessage(formatMutationSuccessMessage('Run cancelled.', result));
      setCancelRunId('');
      await onRefresh();
    } catch (err) {
      setError(apiErrorMessage(err, 'Cancel run failed.'));
    } finally {
      setBusy('');
    }
  }

  async function finalizeRun(id: string) {
    if (!id) return;
    setFinalizeRunId(id);
  }

  async function confirmFinalizeRun() {
    if (!canManageScans) return;
    const id = finalizeRunId;
    if (!id) return;
    await runAction(setBusy, setError, setMessage, `finalize-${id}`, () => requestJson(config, session, `/v1/test-runs/${id}/finalize`, { method: 'POST' }), 'Run finalized after observation window.', onRefresh);
    setFinalizeRunId('');
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
    if (!await confirm({
      title: 'Export evidence chain JSON',
      description: `Export evidence chain JSON?\n\nThis fetches up to 20 recent run details for verdict correlation.\n\n${summary}`,
      confirmLabel: 'Export JSON',
      confirmTone: 'default'
    })) return;
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
      const custody = await buildEvidenceCustodyManifest(exportData.payload, session.tenant_id ?? data.state?.tenant_id ?? 'unknown');
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

  // Prototype-parity: #screen-checks and #screen-findings page-heads expose a Refresh
  // action. Reuses the portal onRefresh so the catalog / findings reflect fresh state.
  async function handleSurfaceRefresh() {
    setBusy('refresh');
    setError('');
    setMessage('');
    try {
      await onRefresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Refresh failed.');
    } finally {
      setBusy('');
    }
  }

  if (route === 'checks') {
    ensureFunctionalSurfaceStyles();
    const columns: TableColumn<DataItem>[] = [
      {
        key: 'check',
        label: 'Check',
        render: (item) => {
          const checkId = getString(item, ['check_id'], '');
          const targets = Array.isArray(item.supported_targets)
            ? (item.supported_targets as unknown[]).map(String)
            : [];
          return (
            <span className="catalog-check-primary">
              <strong>{getString(item, ['name', 'title', 'check_id'], '—')}</strong>
              <code className="traffic-path-label" title={checkId}>{checkId || 'No check ID'}</code>
              {targets.length ? <small>Targets: {targets.join(', ')}</small> : null}
            </span>
          );
        }
      },
      {
        key: 'family',
        label: 'Family',
        render: (item) => (
          <Badge tone="info" title="Vector family from the check catalog">
            {formatVectorFamilyLabel(getString(item, ['vector_family'], ''))}
          </Badge>
        )
      },
      {
        key: 'mode',
        label: 'Mode & safety',
        render: (item) => {
          const safetyClass = getString(item, ['safety_class'], 'unknown');
          return (
            <span className="catalog-cell-stack">
              <Badge tone={checkModeBadgeTone(safetyClass)}>{formatCheckModeLabel(safetyClass)}</Badge>
              <small>{formatCheckBoundLabel(item)}</small>
            </span>
          );
        }
      },
      {
        key: 'evidence',
        label: 'Evidence tier',
        render: (item) => {
          const tier = getString(item, ['evidence_tier'], '');
          const required = Array.isArray(item.evidence_required) ? item.evidence_required.map(String) : [];
          return (
            <span className="catalog-cell-stack">
              {tier ? <Badge tone="muted" title="Derived evidence tier from catalog contract">{tier}</Badge> : <span className="muted">Not recorded</span>}
              {required.length ? <small title={required.join(', ')}>{required.length} required {pluralize(required.length, 'signal')}</small> : null}
            </span>
          );
        }
      },
      {
        key: 'expected',
        label: 'Expected behavior',
        render: (item) => {
          const expected = getString(item, ['expected_behavior', 'expected_result'], '');
          const description = getString(item, ['description', 'summary'], '');
          return (
            <span className="catalog-cell-stack">
              <strong>{expected ? formatSnakeLabel(expected) : 'Declared per target'}</strong>
              {description ? <small title={description}>{truncateText(description, 86)}</small> : null}
            </span>
          );
        }
      },
      {
        key: 'result',
        label: 'Last result',
        render: (item) => {
          const checkId = getString(item, ['check_id'], '');
          const latest = latestCheckVerdicts.get(checkId);
          const safetyClass = getString(item, ['safety_class'], '');
          const verdict = latest?.verdict || (safetyClass === 'soc_gated' ? 'request' : '');
          const badge = <Badge tone={catalogVerdictBadgeTone(verdict)}>{verdict ? (verdict === 'request' ? 'Request required' : plainVerdictLabel(verdict)) : 'Untested'}</Badge>;
          return latest?.runId
            ? <AnchorButton size="sm" variant="ghost" href={buildDetailHref('run-detail', latest.runId)} aria-label={`Open latest run for ${checkId}`}>{badge}</AnchorButton>
            : badge;
        }
      }
    ];
    const checksLoadError = data.loadErrors.checks ?? '';
    return (
      <div className="content validation-catalog-page">
        <PageHeader
          route="checks"
          eyebrow="Validation catalog"
          title="Checks"
          description="Every bounded customer-runnable check and governed scenario, with execution class, evidence tier, expected behavior, and latest result."
          actions={<Button variant="secondary" size="sm" loading={busy === 'refresh'} disabled={busy !== ''} onClick={() => void handleSurfaceRefresh()}>Refresh</Button>}
        />
        <PageContextSummary>
          {checksLoadError ? 'Check catalog unavailable' : <><span className="tabular-nums">{data.checks.length}</span> checks · <span className="tabular-nums">{checkSafetyCounts.safe}</span> customer-runnable · <span className="tabular-nums">{checkSafetyCounts.soc}</span> governed</>}
        </PageContextSummary>
        <MutationFeedbackBanner message={message} error={error} neutral />
        <Card>
          <CardHeader>
            <div>
              <CardTitle>Check catalog</CardTitle>
              <CardDescription><span className="tabular-nums">{visibleChecks.length}</span> of <span className="tabular-nums">{data.checks.length}</span> checks. Open any row for bounds, taxonomy, setup, and recent evidence.</CardDescription>
            </div>
            <Badge tone="muted">Evidence backed</Badge>
          </CardHeader>
          <CardContent className="stack-tight">
            <div className="catalog-filter-grid" role="group" aria-label="Check catalog filters">
              <label className="field catalog-search-field">
                <span>Search</span>
                <span className="catalog-search-control"><Search size={15} aria-hidden="true" /><input type="search" value={checkQuery} onChange={(event) => setCheckQuery(event.target.value)} placeholder="Search name, ID, family, or evidence tier" /></span>
              </label>
              <Select label="Vector family" value={checkFilter} options={CHECK_FAMILY_FILTER_OPTIONS} onChange={(value) => setCheckFilter(value as CheckFamilyTabId)} />
              <Select label="Safety class" value={checkSafetyScope} options={CHECK_SAFETY_SCOPE_TABS.map((tab) => ({ value: tab.id, label: `${tab.label} (${checkSafetyCounts[tab.id]})` }))} onChange={(value) => setCheckSafetyScope(value as CheckSafetyScopeId)} />
              <Select label="Last verdict" value={checkStatusFilter} options={CHECK_STATUS_FILTER_OPTIONS} onChange={setCheckStatusFilter} />
            </div>
            <DataTable
              className="validation-catalog-table"
              columns={columns}
              items={visibleChecks}
              getRowId={(item, index) => getString(item, ['check_id'], String(index))}
              getRowProps={(item) => {
                const checkId = getString(item, ['check_id'], '');
                return checkId ? buildDetailHashRowProps('check-detail', checkId, `Open ${checkId}`) : {};
              }}
              loadError={checksLoadError}
              onRetry={() => void handleSurfaceRefresh()}
              empty={data.checks.length === 0
                ? <EmptyState icon={ListChecks} title="No checks in catalog" body="The check catalog appears after tenant provisioning. No execution capability is inferred from an empty response." />
                : <EmptyState icon={ListChecks} title="No checks match these filters" body="Adjust search, vector family, safety class, or last result." />}
            />
          </CardContent>
        </Card>
      </div>
    );
  }

  if (route === 'runs') {
    ensureFunctionalSurfaceStyles();
    const runColumns: TableColumn<DataItem>[] = [
      {
        key: 'run',
        label: 'Run',
        render: (item) => {
          const scanId = getString(item, ['scan_id'], '');
          return (
            <span className="catalog-cell-stack">
              <code className="traffic-path-label" title={getString(item, ['id'])}>{getString(item, ['id'])}</code>
              {scanId ? (
                <a className="scan-link small" href={buildDetailHref('scan-detail', scanId)} aria-label={`Open parent scan ${scanId}`} onClick={(event) => event.stopPropagation()}>Scan</a>
              ) : null}
            </span>
          );
        }
      },
      {
        key: 'group',
        label: 'Target group',
        render: (item) => resolveTargetGroupName(data.targetGroups, getString(item, ['target_group_id']))
      },
      {
        key: 'checks',
        label: 'Checks',
        render: (item) => {
          const checkCount = getNumber(item, ['check_count'], -1);
          if (checkCount >= 0) return <span className="num tabular-nums">{checkCount}</span>;
          return checkDisplayName(data.checks, getString(item, ['check_id']), getString(item, ['id']));
        }
      },
      {
        key: 'mode',
        label: 'Mode',
        render: (item) => {
          const checkId = getString(item, ['check_id'], '');
          const check = data.checks.find((entry) => getString(entry, ['check_id'], '') === checkId);
          const safetyClass = getString(check ?? {}, ['safety_class'], '');
          const tier = getString(check ?? {}, ['evidence_tier'], '');
          return safetyClass ? (
            <span className="catalog-cell-stack">
              <Badge tone={checkModeBadgeTone(safetyClass)}>{formatCheckModeLabel(safetyClass)}</Badge>
              {tier ? <small>{tier}</small> : null}
            </span>
          ) : <span className="muted">—</span>;
        }
      },
      {
        key: 'status',
        label: 'Status',
        render: (item) => {
          const status = getString(item, ['status'], 'planned');
          const inProgress = isInProgressRunStatus(status);
          const startedAgo = inProgress ? formatStartedAgo(item.started_at ?? item.created_at) : '';
          return (
            <span className="run-status-cell">
              <span className="run-status-line">
                {inProgress ? <span className="run-live-dot" aria-hidden="true" /> : null}
                <Badge tone={runStatusBadgeTone(status)} title="Recorded run lifecycle status">
                  {formatRunStatusLabel(status)}
                </Badge>
              </span>
              {startedAgo ? <span className="muted run-status-sub">{startedAgo}</span> : null}
            </span>
          );
        }
      },
      {
        key: 'verdict',
        label: 'Verdict',
        render: (item) => {
          const verdict = hasEvidenceBackedVerdict(item, data.evidence) ? getRunVerdictValue(item) : '';
          if (!verdict) return <span className="muted">No result yet</span>;
          const verdictRecord = getNestedItem(item, ['verdict']);
          const rawConfidence = getNumber(verdictRecord ?? {}, ['confidence_pct', 'confidence'], -1);
          const confidence = rawConfidence < 0 ? '' : rawConfidence <= 1 ? `${Math.round(rawConfidence * 100)}% confidence` : `${Math.round(rawConfidence)}% confidence`;
          return <span className="catalog-cell-stack"><Badge tone={verdictBadgeTone(verdict)} title="Evidence-backed run verdict">{plainVerdictLabel(verdict)}</Badge>{confidence ? <small>{confidence}</small> : null}</span>;
        }
      },
      {
        key: 'duration',
        label: 'Duration',
        render: (item) => <code className="traffic-path-label">{formatRunDuration(item)}</code>
      },
      {
        key: 'started',
        label: 'Started',
        render: (item) => <span className="muted">{formatDate(item.started_at ?? item.created_at)}</span>
      },
      {
        key: 'actions',
        label: 'Actions',
        render: (item) => {
          const id = getString(item, ['id'], '');
          // Same gate the run-detail page uses: cancel and force-finalize are offered while
          // the run is still in flight (planned/running/collecting).
          if (!id || !isCancellableRunStatus(getString(item, ['status'], '')) || !canManageScans) {
            return <span className="muted">—</span>;
          }
          return (
            <div className="row-end-actions" onClick={(event) => event.stopPropagation()}>
              <Button
                size="sm"
                variant="danger"
                disabled={busy !== ''}
                loading={busy === `cancel-${id}`}
                onClick={(event) => { event.stopPropagation(); void cancelRun(id); }}
              >
                Cancel
              </Button>
              <Button
                size="sm"
                variant="ghost"
                disabled={busy !== ''}
                loading={busy === `finalize-${id}`}
                onClick={(event) => { event.stopPropagation(); void finalizeRun(id); }}
              >
                Finalize
              </Button>
            </div>
          );
        }
      }
    ];
    const canOpenVectorLibrary = data.targetGroups.length > 0 && data.checks.some((check) => getString(check, ['safety_class']) === 'safe');
    const startDisabledReason = data.targetGroups.length === 0
      ? 'Declare a target group first.'
      : !data.checks.some((check) => getString(check, ['safety_class']) === 'safe')
        ? 'No customer-runnable check in catalog.'
        : '';
    const runStatusOptions = [
      { value: 'all', label: 'All statuses' },
      ...[...new Set(data.runs.map((run) => getString(run, ['status'], '')).filter(Boolean))].sort().map((status) => ({ value: status, label: formatRunStatusLabel(status) }))
    ];
    const scanStatusOptions = [
      { value: 'all', label: 'All scan statuses' },
      ...SCAN_STATUSES.map((status) => ({ value: status, label: scanStatusLabel(status) }))
    ];
    const visibleScans = scanStatusFilter === 'all'
      ? data.validationScans
      : data.validationScans.filter((scan) => getString(scan, ['status'], '') === scanStatusFilter);
    const liveCounts = [
      inFlightRuns.length > 0 ? `${inFlightRuns.length} active ${pluralize(inFlightRuns.length, 'run')}` : '',
      activeScans.length > 0 ? `${activeScans.length} active ${pluralize(activeScans.length, 'scan')}` : ''
    ].filter(Boolean).join(', ');
    const runHeadActions = (
      <RunsPageHeadActions
        onRefresh={() => void onRefresh()}
        onStartSafeRun={() => { window.location.hash = '#checks'; }}
        onStartScan={canManageScans ? () => setScanLauncher({ mode: 'create', scan: null }) : undefined}
        refreshBusy={busy === 'refresh-runs'}
        safeRunBusy={false}
        safeRunDisabled={busy !== '' || !canOpenVectorLibrary}
      />
    );
    const runSocGatePanel = (
      <RunsSocGatePanel
        data={data}
        config={config}
        session={session}
        onRefresh={onRefresh}
        onMessage={setMessage}
        onError={setError}
        busy={busy}
        setBusy={setBusy}
      />
    );
    const validationScansTable = (
      <ValidationScansTable
        scans={visibleScans}
        meta={data.validationScansMeta}
        loadError={data.loadErrors.validationScans}
        onRetry={() => void onRefresh(['validationScans'])}
        canManage={canManageScans}
        config={config}
        session={session}
        onEdit={(scan) => setScanLauncher({ mode: 'edit', scan })}
        onReschedule={(scan) => setScanLauncher({ mode: 'reschedule', scan })}
        onCancelled={(scan) => {
          setError('');
          setMessage(`Scan ${scanDisplayName(scan)} is ${scanStatusLabel(getString(scan, ['status'], '')).toLowerCase()}.`);
          void onRefresh(['validationScans', 'runs']);
        }}
      />
    );
    const getRunRowProps = (item: DataItem) => {
      const id = getString(item, ['id'], '');
      return buildDetailHashRowProps('run-detail', id, `Open ${id} detail`);
    };
    const runsEmptyState = renderFriendlyEmptyState({
      icon: Activity,
      title: 'No test runs yet.',
      body: 'Start a validation run after declaring target scope.',
      actionLabel: 'Open vector library',
      onAction: () => { window.location.hash = '#checks'; }
    });
    const runModals = (
      <>
        <ConfirmModal
          open={Boolean(cancelRunId)}
          title="Cancel this run in progress?"
          description={<p>Run {cancelRunId} stops collecting and records no verdict.</p>}
          confirmLabel="Cancel run"
          dismissLabel="Keep run"
          busy={busy === `cancel-${cancelRunId}`}
          onCancel={() => setCancelRunId('')}
          onConfirm={() => void confirmCancelRun()}
        />
        <ConfirmModal
          open={Boolean(finalizeRunId)}
          title="Force finalize this run now?"
          description={<p>This locks the verdict.</p>}
          confirmLabel="Force finalize"
          busy={busy === `finalize-${finalizeRunId}`}
          onCancel={() => setFinalizeRunId('')}
          onConfirm={() => void confirmFinalizeRun()}
        />
        <ValidationScanLauncher
          open={Boolean(scanLauncher)}
          mode={scanLauncher?.mode ?? 'create'}
          scan={scanLauncher?.scan ?? null}
          config={config}
          session={session}
          checks={data.checks}
          targetGroups={data.targetGroups}
          onClose={() => setScanLauncher(null)}
          onScheduled={(scan, mode) => {
            setScanLauncher(null);
            setError('');
            setMessage(mode === 'edit'
              ? `Scan ${scanDisplayName(scan)} updated. Scheduled for ${formatDate(scan.scheduled_for)}.`
              : `Scan ${scanDisplayName(scan)} scheduled for ${formatDate(scan.scheduled_for)}.`);
            void onRefresh(['validationScans']);
          }}
        />
      </>
    );
    if (runsVariant === 'refined') {
      const refinedProps: RunsRefinedProps = {
        data,
        config,
        session,
        onRefresh,
        variant: runsVariant,
        onVariantChange: setRunsVariant,
        busy,
        message,
        error,
        canManageScans,
        canRequestHighScale,
        inFlightRunCount: inFlightRuns.length,
        activeScanCount: activeScans.length,
        liveCounts,
        canOpenVectorLibrary,
        startDisabledReason,
        headerActions: runHeadActions,
        socGatePanel: runSocGatePanel,
        scanStatusFilter,
        scanStatusOptions,
        onScanStatusFilterChange: setScanStatusFilter,
        validationScansTable,
        runColumns,
        filteredRuns,
        runStatusFilter,
        runStatusOptions,
        onRunStatusFilterChange: setRunStatusFilter,
        getRunRowProps,
        runsEmptyState,
        modals: runModals
      };
      return <RunsRefined {...refinedProps} />;
    }
    return (
      <div className="content validation-runs-page">
        <PageHeader
          route="runs"
          eyebrow="Validation history"
          title="Test runs"
          description="Review safe checks and direct validation runs with lifecycle state, correlated verdict, confidence when published, and sealed evidence."
          actions={(
            <>
              <VariantSwitch value={runsVariant} onChange={setRunsVariant} />
              {runHeadActions}
            </>
          )}
        />
        <PageContextSummary>
          <span className="tabular-nums">{data.runs.length}</span>{` ${pluralize(data.runs.length, 'run')} · `}<span className="tabular-nums">{inFlightRuns.length}</span> in progress
        </PageContextSummary>
        {inFlightRuns.length > 0 || activeScans.length > 0 ? (
          <div className="form-banner info" role="status" aria-live="polite">
            Runs in progress — live status auto-refreshes every 8s ({liveCounts}). Verdicts appear when the observation window closes.
          </div>
        ) : null}
        {!canOpenVectorLibrary && startDisabledReason ? (
          <div className="form-banner neutral" role="note">
            Open the vector library once ready — {startDisabledReason}
          </div>
        ) : null}
        <MutationFeedbackBanner message={message} error={error} neutral />
        <Card className="validation-scans-card">
          <CardHeader>
            <div><CardTitle>Validation scans</CardTitle><CardDescription>Multi-check scans run one bounded child run at a time. Scheduled scans dispatch at their planned time and stay editable until then.</CardDescription></div>
            <Badge tone="muted">{data.validationScans.length} {pluralize(data.validationScans.length, 'scan')}</Badge>
          </CardHeader>
          <CardContent className="stack-tight">
            <div className="catalog-filter-grid" role="group" aria-label="Validation scan filters">
              <Select label="Scan status" value={scanStatusFilter} options={scanStatusOptions} onChange={setScanStatusFilter} />
            </div>
            {validationScansTable}
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <div><CardTitle>Run history</CardTitle><CardDescription>Open a row for probe results, correlation, and custody chain.</CardDescription></div>
          </CardHeader>
          <CardContent className="stack-tight">
            <div className="catalog-filter-grid" role="group" aria-label="Run history filters">
              <Select label="Lifecycle status" value={runStatusFilter} options={runStatusOptions} onChange={setRunStatusFilter} />
            </div>
            <DataTable
              className="validation-runs-table"
              columns={runColumns}
              items={filteredRuns}
              getRowProps={getRunRowProps}
              empty={runsEmptyState}
              loadError={data.loadErrors.runs}
              onRetry={onRefresh ? () => void onRefresh() : undefined}
            />
          </CardContent>
        </Card>
        {runSocGatePanel}
        {runModals}
      </div>
    );
  }

  if (route === 'findings') {
    const findingKpis = computeFindingKpis(data.findings);
    const findingsLoadError = data.loadErrors.findings ?? '';
    if (findingsVariant === 'refined') {
      const refinedProps: FindingsRefinedProps = {
        data,
        config,
        session,
        variant: findingsVariant,
        onVariantChange: setFindingsVariant,
        busy,
        message,
        error,
        findingKpis,
        findingsLoadError,
        onRefresh: () => void handleSurfaceRefresh()
      };
      return <FindingsRefined {...refinedProps} />;
    }
    return (
      <div className="content validation-findings-page">
        <PageHeader
          route="findings"
          eyebrow="Triage & remediate"
          title="Findings"
          description="Every finding links an observed verdict to evidence, declared business context, ownership, SLA, and a concrete remediation path."
          actions={(
            <>
              <VariantSwitch value={findingsVariant} onChange={setFindingsVariant} />
              <Button variant="secondary" size="sm" loading={busy === 'refresh'} disabled={busy !== ''} onClick={() => void handleSurfaceRefresh()}>Refresh</Button>
            </>
          )}
        />
        <PageContextSummary>
          {findingsLoadError ? 'Finding inventory unavailable' : <><span className="tabular-nums">{findingKpis.openCount}</span> open · <span className="tabular-nums">{findingKpis.acceptedRiskCount}</span> accepted risk · <span className="tabular-nums">{findingKpis.closed30dCount}</span> closed in 30d · <span className="tabular-nums">{findingKpis.slaBreachCount}</span> SLA breached</>}
        </PageContextSummary>
        <MutationFeedbackBanner message={message} error={error} neutral />
        <Card>
          <CardHeader>
            <div><CardTitle>Finding queue</CardTitle><CardDescription>One row per rule, with every asset it was observed on. Open a row to see the affected assets, then any asset for explanation, remediation, safe retest, and custody export.</CardDescription></div>
            <Badge tone={findingKpis.slaBreachCount > 0 ? 'danger' : 'muted'}>{findingKpis.slaBreachCount} SLA breached</Badge>
          </CardHeader>
          <CardContent className="findings-surface-wrap">
            <FindingsListView findings={data.findings} checks={data.checks} targetGroups={data.targetGroups} targets={data.targets} loadError={findingsLoadError} onRetry={() => void handleSurfaceRefresh()} />
          </CardContent>
        </Card>
      </div>
    );
  }

  return (
    <div className="content">
      <PageHeader route={route} />
      <EmptyState icon={ListChecks} title="Validation surface unavailable." body="This route is not wired in the revamp navigation." actionLabel="Open dashboard" actionHref="#dashboard" />
    </div>
  );
}
