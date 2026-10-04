import { useCallback, useEffect, useMemo, useRef, useState, type FormEvent, type HTMLAttributes, type KeyboardEvent, type ReactNode } from 'react';
import { Activity, Bot, ClipboardList, FileCheck2, FileText, Network, ShieldCheck, Siren, Target, TriangleAlert, UserCog, Users } from 'lucide-react';
import { FindingExplanationPanel } from '../components/findings/finding-explanation-panel';
import { Badge, type BadgeProps } from '../components/ui/badge';
import { AnchorButton, Button } from '../components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../components/ui/card';
import { EmptyState } from '../components/ui/empty-state';
import { RoleRestrictedNotice } from '../components/ui/role-restricted';
import { canReadDataset, sessionHasPermission } from '../lib/dataset-access.mjs';
import { DataTable, type TableColumn } from '../components/ui/table';
import { Select } from '../components/ui/select';
import { Tabs } from '../components/ui/tabs';
import { buildApiHeaders, isStaffSocRole, requestJson, requestSocJson } from '../lib/api';
import { apiErrorMessage, humanizeErrorCode } from '../lib/error-messages';
import { ROUTE_BY_ID } from '../lib/navigation';
import { buildDetailHref, getRouteEntityId, getRouteParam, getRouteTenantId, openEvidenceInspector } from '../lib/route-params';
import {
  describeScheduleDispatch,
  formatSafeWindowList,
  formatScheduleInstant,
  ScheduleActions,
  scheduleCheck,
  scheduleCheckHref,
  scheduleDisplayName,
  scheduleSafeWindows,
  ScheduleStateBadge,
  scheduleTarget
} from './refined/policies-refined';
import { buildEvidenceCustodyManifest, CUSTODY_CONTENT_CANONICALIZATION } from '../lib/custody';
import type { DataItem, PortalConfig, PortalData, RouteId, Session } from '../lib/types';
import { formatDate, formatDurationSeconds, formatNumber, formatSeverityLabel, scoreTone, triggerJsonDownload, triggerTextDownload } from '../lib/utils';
import { hasEvidenceBackedVerdict } from '../lib/run-verdict';
import { CapabilityProbeResultsPanel } from '../components/runs/capability-probe-panel';
import { useFindingPages } from '../components/findings/use-server-findings';
import { ConfirmModal, formatMutationSuccessMessage, useConfirmModal } from '../lib/crud-ui';
import { RunTimelineViz, TrafficPathPanel, TruthTablePanel, VerdictExplanationPanel } from '../components/runs/run-proof-panels';
import {
  isSignedProbeEvidenceEvent,
} from '../lib/verdict-explanation';
import { findingSlaDueAt, findingStatus, isFindingSlaBreach, resolveFindingRetestAction } from '../lib/findings-helpers';
import {
  authorizationArtifactPurpose,
  authorizationArtifactTitle,
  authorizationArtifactTypesForRequest,
  bestArtifactForType,
  buildLifecycleTimeline,
  buildMetadataArtifactUploadBody,
  explainArtifactReviewStatus,
  packRequirementForType,
  socDevScheduleWindow
} from '../lib/high-scale';
import { routeTabs } from '../lib/prototype-manifest';
import { ReadinessGauge } from '../components/charts/readiness-gauge';
import { runStatusTone as runStatusBadgeTone } from '../lib/status-tone';
import {
  CustomerPageStyles,
  MetricCard,
  PageContextSummary,
  REPORT_FORMAT_FALLBACK_OPTIONS,
  ReportExportMenu,
  ReportExportResult,
  reportKindIsFramework,
  reportKindLabel,
  reportOptionsFromCapabilities,
  useReportExport
} from './page-components';
import { effectivePolicyTargetKind, isPolicyTargetCompatible } from '../components/policies/target-group-picker';
import { TargetGroupDetailView as TargetGroupDetailViewRevamp } from './target-group-detail-view';
import { TargetDetailView } from './target-detail-view';
import { FindingDetailView as FindingDetailViewRevamp } from './finding-detail-view';
// @ts-ignore Plain ESM keeps executive labels directly testable with node:test.
import { plainCheckName, plainCodeLabel, plainFindingTitle, plainInlineText, plainVerdictLabel } from '../lib/plain-language.mjs';


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

function getNestedNumber(item: DataItem | null | undefined, path: string[], fallback = 0) {
  let current: unknown = item;
  for (const key of path) {
    if (!current || typeof current !== 'object' || Array.isArray(current)) return fallback;
    current = (current as DataItem)[key];
  }
  return typeof current === 'number' && Number.isFinite(current) ? current : fallback;
}

function getNestedArray(item: DataItem | null | undefined, path: string[]) {
  let current: unknown = item;
  for (const key of path) {
    if (!current || typeof current !== 'object' || Array.isArray(current)) return [];
    current = (current as DataItem)[key];
  }
  return Array.isArray(current) ? current as DataItem[] : [];
}

function getNestedItem(item: DataItem | null | undefined, path: string[]) {
  let current: unknown = item;
  for (const key of path) {
    if (!current || typeof current !== 'object' || Array.isArray(current)) return null;
    current = (current as DataItem)[key];
  }
  return current && typeof current === 'object' && !Array.isArray(current) ? current as DataItem : null;
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

function formatFactorLabel(value: string) {
  return value.replace(/_/g, ' ');
}

const SIGNAL_TYPE_LABELS: Record<string, string> = {
  probe_result: 'Probe result',
  verdict_published: 'Verdict published',
  run_started: 'Run started',
  run_cancelled: 'Run cancelled'
};

function humanizeSignalType(value: string) {
  const key = value.trim();
  if (!key) return 'Event';
  return SIGNAL_TYPE_LABELS[key] ?? formatFactorLabel(key);
}

function checkDisplayName(checks: DataItem[], checkId: string) {
  const check = checks.find((entry) => getString(entry, ['check_id'], '') === checkId);
  return plainCheckName(getString(check ?? {}, ['name', 'title'], checkId));
}

function runDisplayLabel(runs: DataItem[], runId: string) {
  const run = runs.find((entry) => getString(entry, ['id'], '') === runId);
  if (!run) return runId;
  const checkId = getString(run, ['check_id'], '');
  const when = formatDate(run.started_at ?? run.created_at);
  return checkId ? `${checkId} · ${when}` : when || runId;
}

function targetDisplayLabel(targets: DataItem[], targetId: string) {
  const target = targets.find((entry) => getString(entry, ['id'], '') === targetId);
  return getString(target ?? {}, ['value', 'hostname', 'label'], targetId);
}

const STAFF_ENTITLEMENT_LABELS: Record<string, string> = {
  waf_posture: 'WAF posture',
  external_discovery: 'External discovery',
  connectors: 'Connectors',
  high_scale_program: 'High-scale program'
};

const SUPPLY_CHAIN_EXPOSURE_TYPES = [
  { id: 'dangling_cname', label: 'Dangling CNAME' },
  { id: 'subdomain_takeover', label: 'Subdomain takeover risk' },
  { id: 'orphan_record', label: 'Orphan DNS record' },
  { id: 'customer_declared', label: 'Customer-declared exposure' }
] as const;

const SUPPLY_CHAIN_PHASE_LABELS: Record<string, { label: string; description: string }> = {
  AP2_manual_custody: { label: 'Manual custody (AP2)', description: 'Customer retains manual custody before governed activation.' },
  AP3_governed_active: { label: 'Governed active (AP3)', description: 'Governed active protection with signed authorization.' }
};

function discoveryEyebrow(state: string) {
  const normalized = state.toLowerCase();
  if (['approved', 'approved_target', 'imported', 'entity'].includes(normalized)) return 'Discovery entity';
  if (normalized === 'rejected') return 'Rejected candidate';
  return 'Discovery candidate';
}

function formatConfidencePercent(entity: DataItem) {
  const raw = entity.confidence ?? entity.confidence_score;
  if (typeof raw === 'number' && Number.isFinite(raw)) {
    const pct = raw <= 1 ? Math.round(raw * 100) : Math.round(raw);
    return `${pct}%`;
  }
  const text = getString(entity, ['confidence', 'confidence_score'], '');
  return text || '—';
}




/** Human-readable byte size for evidence artifact KPIs; returns '' when size is unknown so callers can omit gracefully. */
function formatEvidenceSize(entity: DataItem): string {
  const raw = getNestedNumber(entity, ['size_bytes'], NaN);
  const bytes = Number.isFinite(raw) ? raw : getNestedNumber(entity, ['metadata', 'size_bytes'], NaN);
  if (!Number.isFinite(bytes) || bytes < 0) return '';
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

/** Build a `key: value` code block, omitting rows whose value is absent so no fake data is rendered. */
function evidenceCodeBlock(rows: Array<[string, string]>): string {
  return rows
    .filter(([, value]) => value && value !== '—')
    .map(([key, value]) => `${key}: ${value}`)
    .join('\n');
}

type AuthorizationArtifactDraft = {
  filename: string;
  content_sha256: string;
  custody_id: string;
};

function TimelinePanel({ items }: { items: Array<{ label: string; at?: unknown }> }) {
  if (items.length === 0) {
    return <p className="muted">No timeline milestones recorded for this entity.</p>;
  }
  return (
    <div className="timeline-list">
      {items.map((item, index) => (
        <div key={`${item.label}-${index}`}>
          <span aria-hidden="true" />
          <div>
            <strong>{item.label}</strong>
            <p>{formatDate(item.at)}</p>
          </div>
        </div>
      ))}
    </div>
  );
}

const DETAIL_GROUP_LABELS: Record<string, string> = {
  scope: 'Scope',
  validation: 'Validation',
  posture: 'Posture',
  governance: 'Governance',
  staff: 'Staff'
};

type StatusBadgeTone = NonNullable<BadgeProps['tone']>;

const DETAIL_SKELETON_KV_ROWS = 6;
const DETAIL_SKELETON_TAB_COUNT = 4;

function normalizeStatusKey(value: string) {
  return value.trim().toLowerCase().replace(/\s+/g, '_');
}

function formatStatusLabel(value: string, fallback = '—') {
  const trimmed = value.trim();
  if (!trimmed) return fallback;
  const label = trimmed.replace(/_/g, ' ');
  return label.charAt(0).toUpperCase() + label.slice(1);
}



function verdictBadgeTone(verdict: string): StatusBadgeTone {
  const key = normalizeStatusKey(verdict);
  if (key === 'pass') return 'success';
  if (['fail', 'failed', 'gap', 'edge_exposed', 'bypassable', 'penetrated', 'exposed', 'unprotected'].includes(key)) return 'danger';
  if (key === 'inconclusive') return 'warn';
  return 'info';
}

function findingSeverityBadgeTone(severity: string): StatusBadgeTone {
  const key = normalizeStatusKey(severity);
  if (['critical', 'high'].includes(key)) return 'danger';
  if (['medium', 'moderate'].includes(key)) return 'warn';
  if (['low', 'info'].includes(key)) return 'info';
  return 'muted';
}

function findingStatusBadgeTone(status: string): StatusBadgeTone {
  const key = normalizeStatusKey(status);
  if (key === 'closed') return 'success';
  if (key === 'accepted_risk') return 'muted';
  if (key === 'open') return 'warn';
  return 'info';
}

function discoveryEntityStateBadgeTone(state: string): StatusBadgeTone {
  const key = normalizeStatusKey(state);
  if (['approved', 'active', 'entity', 'imported'].includes(key)) return 'success';
  if (key === 'rejected') return 'danger';
  return 'warn';
}

function signupRequestStateTone(state: string): StatusBadgeTone {
  const key = normalizeStatusKey(state);
  if (['approved', 'provisioned', 'active'].includes(key)) return 'success';
  if (['rejected', 'denied', 'cancelled', 'canceled'].includes(key)) return 'danger';
  if (['under_review', 'reviewing', 'in_review'].includes(key)) return 'warn';
  if (['submitted', 'pending', 'recorded'].includes(key)) return 'info';
  return 'muted';
}

function supplyChainExposureLabel(type: string) {
  const match = SUPPLY_CHAIN_EXPOSURE_TYPES.find((entry) => entry.id === type);
  return match?.label ?? formatStatusLabel(type);
}

function highScaleStateBadgeTone(state: string): StatusBadgeTone {
  const key = normalizeStatusKey(state);
  if (['closed', 'completed'].includes(key)) return 'success';
  if (['running', 'scheduled', 'approved'].includes(key)) return 'info';
  if (['stopped', 'under_review', 'submitted'].includes(key)) return 'warn';
  if (['rejected', 'failed'].includes(key)) return 'danger';
  return 'muted';
}

function artifactReviewBadgeTone(status: string): StatusBadgeTone {
  const key = normalizeStatusKey(status);
  if (key === 'accepted') return 'success';
  if (key === 'rejected') return 'danger';
  if (key === 'pending_review' || key === 'pending') return 'warn';
  return 'info';
}

function reportStatusBadgeTone(status: string): StatusBadgeTone {
  const key = normalizeStatusKey(status);
  if (['ready', 'published', 'complete', 'completed'].includes(key)) return 'success';
  if (['generating', 'pending', 'draft'].includes(key)) return 'info';
  if (['failed', 'error'].includes(key)) return 'danger';
  return 'muted';
}

function cveStageBadgeTone(stage: string): StatusBadgeTone {
  const key = normalizeStatusKey(stage);
  if (['validated', 'mitigated', 'closed'].includes(key)) return 'success';
  if (['triage', 'ingest'].includes(key)) return 'info';
  if (['exposed', 'active'].includes(key)) return 'danger';
  return 'warn';
}

function supplyChainStateBadgeTone(state: string): StatusBadgeTone {
  const key = normalizeStatusKey(state);
  if (key === 'confirmed') return 'danger';
  if (key === 'suspected') return 'warn';
  if (key === 'mitigated' || key === 'resolved') return 'success';
  return 'muted';
}

function subscriptionStatusBadgeTone(status: string): StatusBadgeTone {
  const key = normalizeStatusKey(status);
  if (['active', 'trialing'].includes(key)) return 'success';
  if (['past_due', 'paused'].includes(key)) return 'warn';
  if (['canceled', 'cancelled', 'suspended'].includes(key)) return 'danger';
  return 'info';
}

function lifecycleBadgeTone(state: string): StatusBadgeTone {
  const key = normalizeStatusKey(state);
  if (key === 'active') return 'success';
  if (key === 'suspended') return 'danger';
  if (key === 'pending') return 'warn';
  return 'muted';
}

function StatusBadge({ value, tone, fallback = '—' }: { value: string; tone: StatusBadgeTone; fallback?: string }) {
  const label = formatStatusLabel(value, fallback);
  return <Badge tone={tone}>{label}</Badge>;
}

function VerdictBadge({ value, tone }: { value: string; tone: StatusBadgeTone }) {
  const label = plainVerdictLabel(value);
  return <Badge tone={tone} title={label}>{label}</Badge>;
}

function DetailPageIntro({ route, eyebrow }: { route: RouteId; eyebrow?: string }) {
  const item = ROUTE_BY_ID.get(route);
  const description = item?.description?.trim();
  return (
    <>
      <p className="eyebrow">{eyebrow ?? item?.group}</p>
      <h1>{item?.label ?? 'Detail'}</h1>
      {description ? <p className="muted small">{description}</p> : null}
    </>
  );
}

function DetailKvSkeletonRows({ rows = DETAIL_SKELETON_KV_ROWS }: { rows?: number }) {
  return (
    <>
      {Array.from({ length: rows }, (_, index) => (
        <div key={index}>
          <span className="skeleton skeleton-text" />
          <strong className="skeleton skeleton-text" />
        </div>
      ))}
    </>
  );
}

const DETAIL_LIST_LINKS: Partial<Record<RouteId, { label: string; href: string }>> = {
  'run-detail': { label: 'Test runs', href: '#runs' },
  'target-group-detail': { label: 'Target groups', href: '#target-groups' },
  'target-detail': { label: 'Target groups', href: '#target-groups' },
  'report-detail': { label: 'Reports', href: '#reports' },
  'tenant-detail': { label: 'Admin console', href: '#admin' },
  'finding-detail': { label: 'Findings', href: '#findings' },
  'evidence-detail': { label: 'Findings', href: '#findings' },
  'check-detail': { label: 'Check library', href: '#checks' },
  'policy-detail': { label: 'Validation schedules', href: '#test-policies' },
  'queue-detail': { label: 'SOC console', href: '#internal-soc' }
};

const DETAIL_LINK_ROUTES: RouteId[] = [
  'run-detail',
  'check-detail',
  'policy-detail',
  'target-group-detail',
  'target-detail',
  'tenant-detail',
  'report-detail',
  'finding-detail',
  'evidence-detail',
  'queue-detail'
];

function detailEntityTitle(route: RouteId, entity: DataItem, entityId: string, context?: { checks?: DataItem[] }) {
  if (route === 'run-detail') {
    const checkId = getString(entity, ['check_id'], '');
    return checkId && context?.checks ? checkDisplayName(context.checks, checkId) : getString(entity, ['check_id'], entityId);
  }
  if (route === 'finding-detail') return plainFindingTitle(entity);
  if (route === 'queue-detail') {
    return getString(entity, ['objective', 'reason', 'id'], entityId);
  }
  if (route === 'target-detail') return getString(entity, ['value', 'id'], entityId);
  if (route === 'target-group-detail') return getString(entity, ['name'], entityId);
  if (route === 'report-detail') return getString(entity, ['title'], entityId);
  if (route === 'tenant-detail') {
    const tenant = getNestedItem(entity, ['tenant']) ?? entity;
    return getString(tenant, ['name'], entityId);
  }
  return getString(entity, ['name', 'hostname', 'canonical_url', 'cve_id', 'organization_name', 'id'], entityId);
}

function DetailBreadcrumb({ route, title, entityId }: { route: RouteId; title: string; entityId?: string }) {
  const routeMeta = ROUTE_BY_ID.get(route);
  const listLink = DETAIL_LIST_LINKS[route];
  const listHref = listLink?.href;
  const groupLabel = routeMeta?.group ? (DETAIL_GROUP_LABELS[routeMeta.group] ?? routeMeta.group) : 'Detail';
  const listLabel = listLink?.label ?? routeMeta?.label ?? 'List';
  return (
    <p className="muted stack-tight detail-crumb">
      {listLink && listHref ? (
        <AnchorButton size="sm" variant="ghost" href={listHref}>← Back to {listLink.label}</AnchorButton>
      ) : null}
      {groupLabel} › {listLabel} › {title}
    </p>
  );
}

// Prefixed record IDs plus dotted catalog check IDs (e.g. origin.leak_scan.safe) stay visible as
// secondary engineer-facing text under the plain-English title.
const VISIBLE_DETAIL_ID_RE = /^(?:(?:tgt|tg|run|fnd|evt|agt|env|rpt|scan|usr|ten|wof|id|job|evd|btok|dns)_|[a-z0-9]+(?:_[a-z0-9]+)*(?:\.[a-z0-9]+(?:_[a-z0-9]+)*){1,4}$)/;

function DetailEntityHeading({
  route,
  entityId,
  title,
  eyebrow
}: {
  route: RouteId;
  entityId: string;
  title: string;
  eyebrow?: string;
}) {
  return (
    <>
      {eyebrow ? <p className="eyebrow">{eyebrow}</p> : null}
      <DetailBreadcrumb route={route} title={title} entityId={entityId} />
      <h1>{title}</h1>
      {title !== entityId && VISIBLE_DETAIL_ID_RE.test(entityId) ? <p className="muted"><code>{entityId}</code></p> : null}
    </>
  );
}

function DetailPageHeader({
  route,
  eyebrow,
  entityId,
  title,
  actions
}: {
  route: RouteId;
  eyebrow?: string;
  entityId: string;
  title: string;
  actions?: ReactNode;
}) {
  return (
    <div className="page-head">
      <div>
        <DetailEntityHeading route={route} entityId={entityId} title={title} eyebrow={eyebrow} />
      </div>
      {actions ? <div className="row-actions">{actions}</div> : null}
    </div>
  );
}

function DetailLoadingPlaceholder({
  label = 'Loading…',
  variant = 'page'
}: {
  label?: string;
  variant?: 'page' | 'compact' | 'layout';
}) {
  if (variant === 'compact') {
    return (
      <div className="kv-list" aria-busy="true" aria-label={label}>
        <DetailKvSkeletonRows rows={3} />
      </div>
    );
  }
  if (variant === 'layout') {
    return (
      <div className="detail-layout" aria-busy="true" aria-label={label}>
        <Card density="compact">
          <CardHeader>
            <span className="skeleton skeleton-text" aria-hidden="true" />
            <span className="skeleton skeleton-text" aria-hidden="true" />
          </CardHeader>
          <CardContent className="kv-list">
            <DetailKvSkeletonRows rows={4} />
          </CardContent>
        </Card>
        <Card density="compact" className="detail-primary">
          <CardHeader>
            <span className="skeleton skeleton-text" aria-hidden="true" />
            <span className="skeleton skeleton-text" aria-hidden="true" />
          </CardHeader>
          <CardContent className="kv-list">
            <DetailKvSkeletonRows rows={4} />
          </CardContent>
        </Card>
      </div>
    );
  }
  return (
    <div className="stack-tight" aria-busy="true" aria-label={label}>
      <div className="row-actions" aria-hidden="true">
        {Array.from({ length: DETAIL_SKELETON_TAB_COUNT }, (_, index) => (
          <span key={index} className="skeleton skeleton-row" />
        ))}
      </div>
      <Card density="compact">
        <CardHeader>
          <span className="skeleton skeleton-text" aria-hidden="true" />
          <span className="skeleton skeleton-text" aria-hidden="true" />
        </CardHeader>
        <CardContent className="kv-list">
          <DetailKvSkeletonRows />
        </CardContent>
      </Card>
    </div>
  );
}

function DetailEntityLink({
  route,
  id,
  label
}: {
  route: RouteId;
  id: string;
  label?: string;
}) {
  const resolved = (label ?? id).trim();
  if (!id || id === '—') return <strong>—</strong>;
  if (!DETAIL_LINK_ROUTES.includes(route)) return <strong>{resolved}</strong>;
  return (
    <AnchorButton size="sm" variant="ghost" href={buildDetailHref(route, id)}>
      {resolved}
    </AnchorButton>
  );
}

function DetailKvField({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div>
      <span>{label}</span>
      <strong>{children}</strong>
    </div>
  );
}

function DetailKvHintField({ label, value, hint }: { label: string; value: ReactNode; hint: string }) {
  return (
    <div className="kv-stack">
      <span>{label}</span>
      <div className="stack-tight">
        <strong>{value}</strong>
        <p className="muted small">{hint}</p>
      </div>
    </div>
  );
}

function DetailKvMonoField({ label, value, compact }: { label: string; value: string; compact?: boolean }) {
  return (
    <div className="kv-stack kv-mono-field">
      <span>{label}</span>
      <code className={compact ? 'mono-hash small' : 'mono-hash'} title={value}>{value}</code>
    </div>
  );
}

function DetailCodeBlock({ label, children }: { label: string; children: string }) {
  // Exact machine records remain available to engineers without competing with
  // the customer-facing explanation or being mistaken for presentation copy.
  return (
    <details className="technical-disclosure">
      <summary>Show technical {label.toLocaleLowerCase()}</summary>
      <pre className="codeblock" aria-label={label} tabIndex={0}>
        {children}
      </pre>
    </details>
  );
}

function DetailStatusBanners({
  loadError,
  error,
  message,
  successTone = 'default',
  mode = 'split',
  hideMessageWhenLoadError = true,
  children
}: {
  loadError?: string;
  error?: string;
  message?: string;
  successTone?: 'default' | 'neutral';
  mode?: 'split' | 'combined';
  hideMessageWhenLoadError?: boolean;
  children?: ReactNode;
}) {
  const successClass = successTone === 'neutral' ? 'form-banner neutral' : 'form-banner';
  if (mode === 'combined') {
    const text = error || loadError || message;
    if (!text && !children) return null;
    const isError = Boolean(error || loadError);
    return (
      <div className={isError ? 'form-banner error' : successClass} role={isError ? 'alert' : 'status'}>
        {text}
        {children}
      </div>
    );
  }
  const showActionBanner = Boolean(message || error) && !(hideMessageWhenLoadError && loadError);
  return (
    <>
      {loadError ? (
        <div className="form-banner error" role="alert">
          {loadError}
        </div>
      ) : null}
      {showActionBanner ? (
        <div className={error ? 'form-banner error' : successClass} role={error ? 'alert' : 'status'}>
          {error || message}
          {children}
        </div>
      ) : null}
    </>
  );
}

function useEntityDetail<T extends DataItem>(
  enabled: boolean,
  config: PortalConfig,
  session: Session,
  path: string,
  fallback: T | null
) {
  const [detail, setDetail] = useState<T | null>(fallback);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(enabled && Boolean(path));
  // Bumped by reload(): the detail is otherwise fetched only when `path` changes, so a mutation on
  // the detail page (remove/add target, triage, ...) left the entity showing pre-mutation state.
  const [reloadTick, setReloadTick] = useState(0);
  const reloadWaitersRef = useRef<Array<() => void>>([]);
  const reload = useCallback(() => new Promise<void>((resolve) => {
    reloadWaitersRef.current.push(resolve);
    setReloadTick((n) => n + 1);
  }), []);
  // `fallback` is derived (data.<list>.find(...)) so it is a NEW object identity on
  // every render. Keeping it in the effect deps re-fires the fetch on any re-render and
  // cancels the in-flight request, so the detail can starve and never resolve under
  // render churn. Read it through a ref instead — deps below intentionally omit it.
  const fallbackRef = useRef(fallback);
  fallbackRef.current = fallback;
  const loadedPathRef = useRef('');

  useEffect(() => {
    const settleWaiters = () => {
      const waiters = reloadWaitersRef.current;
      reloadWaitersRef.current = [];
      for (const resolve of waiters) resolve();
    };
    if (!enabled || !path) {
      setDetail(fallbackRef.current);
      setLoading(false);
      settleWaiters();
      return;
    }
    let cancelled = false;
    // A reload of the same entity keeps the current detail on screen (no skeleton, open dialogs
    // stay mounted); only a new path shows the loading state.
    const isReload = loadedPathRef.current === path;
    if (!isReload) setLoading(true);
    setError('');
    requestJson(config, session, path)
      .then((payload) => {
        if (!cancelled) {
          loadedPathRef.current = path;
          setDetail(payload as T);
        }
      })
      .catch((err) => {
        if (!cancelled) {
          if (!isReload) setDetail(fallbackRef.current);
          setError(apiErrorMessage(err, 'Could not load entity detail.'));
        }
      })
      .finally(() => {
        if (!cancelled) {
          setLoading(false);
          settleWaiters();
        }
      });
    return () => {
      cancelled = true;
    };
  }, [config, session, path, enabled, reloadTick]);

  return { detail, error, loading, reload };
}

function useListBackedDetail<T extends DataItem>(
  enabled: boolean,
  config: PortalConfig,
  session: Session,
  listPath: string,
  entityId: string,
  fallback: T | null,
  options: { tenantId?: string; staffSoc?: boolean } = {}
) {
  const [detail, setDetail] = useState<T | null>(fallback);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(enabled && Boolean(entityId));
  const tenantId = options.tenantId;
  const staffSoc = Boolean(options.staffSoc);
  // See useEntityDetail: `fallback` has a fresh identity every render, so it must not
  // gate the fetch effect — read it through a ref and omit it from the deps below.
  const fallbackRef = useRef(fallback);
  fallbackRef.current = fallback;

  useEffect(() => {
    if (!enabled || !entityId) {
      setDetail(fallbackRef.current);
      setLoading(false);
      return;
    }
    let cancelled = false;
    setLoading(true);
    setError('');
    const fetchList = staffSoc
      ? requestSocJson(config, session, listPath, { tenantId })
      : requestJson(config, session, listPath);
    fetchList
      .then((payload) => {
        if (cancelled) return;
        const items = Array.isArray((payload as { items?: unknown }).items)
          ? (payload as { items: T[] }).items
          : [];
        const match = items.find((item) => getString(item, ['id'], '') === entityId) ?? null;
        setDetail(match ?? fallbackRef.current);
        if (!match && !fallbackRef.current) {
          setError('Entity not found in your workspace lists.');
        }
      })
      .catch((err) => {
        if (!cancelled) {
          setDetail(fallbackRef.current);
          setError(apiErrorMessage(err, 'Could not load entity detail.'));
        }
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [config, session, listPath, enabled, entityId, staffSoc, tenantId]);

  return { detail, error, loading };
}

function formatRunDuration(entity: DataItem) {
  const start = entity.started_at ?? entity.created_at;
  const end = getNestedString(entity, ['verdict', 'finalized_at'], '') || entity.completed_at;
  if (!start) return '—';
  if (!end) {
    const status = String(entity.status ?? entity.state ?? '').toLowerCase();
    if (status === 'running' || status === 'collecting' || status === 'in_progress') return 'In progress';
    return '—';
  }
  const ms = new Date(String(end)).getTime() - new Date(String(start)).getTime();
  if (!Number.isFinite(ms) || ms < 0) return '—';
  return formatDurationSeconds(Math.round(ms / 1000));
}

function reportPeriodDisplay(data: PortalData, report: DataItem) {
  const period = getString(report, ['period'], '');
  if (!period) return '—';
  const periods = data.reportCapabilities?.periods;
  const match = Array.isArray(periods)
    ? (periods as DataItem[]).find((entry) => getString(entry, ['value'], '') === period)
    : undefined;
  return match ? getString(match, ['label'], period) : period;
}

type RunEventEvidenceState = {
  entityId: string;
  status: 'loading' | 'loaded' | 'error';
  items: DataItem[];
  error: string;
};

function RunDetailView({
  entity,
  entityId,
  data,
  config,
  session,
  onRefresh,
  runEventState,
  loading,
  loadError
}: {
  entity: DataItem;
  entityId: string;
  data: PortalData;
  config: PortalConfig;
  session: Session;
  onRefresh: () => Promise<void>;
  runEventState: RunEventEvidenceState;
  loading: boolean;
  loadError: string;
}) {
  const [tab, setTab] = useState('summary');
  const [busy, setBusy] = useState('');
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');
  const [confirmCancelOpen, setConfirmCancelOpen] = useState(false);
  const [confirmFinalizeOpen, setConfirmFinalizeOpen] = useState(false);
  const verdict = entity.verdict as DataItem | undefined;
  const runEvents = runEventState.status === 'loaded' ? runEventState.items : [];
  const runEventEvidenceLoading = runEventState.status === 'loading';
  const runEventEvidenceUnavailable = runEventState.status === 'error';
  const probeEvents = runEvents.filter(isSignedProbeEvidenceEvent);
  const trustedEvidenceEvents = probeEvents;
  const relatedEvidence = data.evidence.filter((item) => getString(item, ['test_run_id'], '') === entityId);
  const relatedFindings = data.findings.filter((finding) => getString(finding, ['test_run_id'], '') === entityId);
  const status = getString(entity, ['status'], '');
  const cancellable = ['planned', 'running', 'collecting'].includes(status);
  const canManageRun = sessionHasPermission(session, 'test_run:start');

  async function runAction(label: string, action: () => Promise<unknown>, success: string) {
    setBusy(label);
    setError('');
    setMessage('');
    try {
      await action();
      setMessage(success);
      await onRefresh();
    } catch (err) {
      setError(apiErrorMessage(err, 'Action failed.'));
    } finally {
      setBusy('');
    }
  }

  async function confirmCancelRun() {
    if (!canManageRun) return;
    await runAction(`cancel-${entityId}`, () => requestJson(config, session, `/v1/test-runs/${encodeURIComponent(entityId)}/cancel`, { method: 'POST' }), 'Run cancelled.');
    setConfirmCancelOpen(false);
  }

  async function confirmFinalizeRun() {
    if (!canManageRun) return;
    await runAction(`finalize-${entityId}`, () => requestJson(config, session, `/v1/test-runs/${encodeURIComponent(entityId)}/finalize`, { method: 'POST' }), 'Run finalized after observation window.');
    setConfirmFinalizeOpen(false);
  }

  const milestoneTimeline = [
    { label: 'Run created', at: entity.created_at },
    { label: 'Run started', at: entity.started_at },
    { label: 'Probe window', at: entity.probe_started_at ?? entity.updated_at },
    { label: 'Verdict recorded', at: getNestedString(entity, ['verdict', 'finalized_at'], '') || entity.completed_at }
  ].filter((item) => item.at);

  const runTitle = detailEntityTitle('run-detail', entity, entityId, { checks: data.checks });
  const groupId = getString(entity, ['target_group_id'], '');
  const runTargetId = getString(entity, ['target_id'], '');
  const runCheckId = getString(entity, ['check_id'], '');
  const runTargetGroup = data.targetGroups.find((group) => getString(group, ['id'], '') === groupId) ?? null;
  const groupName = groupId ? getString(runTargetGroup ?? {}, ['name'], groupId) : '—';
  const explicitRunValidationMode = getString(entity, ['validation_mode'], 'external_only');
  const verdictValue = hasEvidenceBackedVerdict(entity, data.evidence)
    ? getNestedString(entity, ['verdict', 'verdict'], runVerdictValue(entity))
    : '';
  const verdictDisplay = verdictValue ? plainVerdictLabel(verdictValue) : 'No result yet';
  const primaryFinding = relatedFindings[0] ?? null;
  const runPolicyId = getString(entity, ['policy_id', 'test_policy_id'], '');
  const runNonceHash = getNestedString(entity, ['correlation', 'nonce_hash'], '');
  const tabOptions = [
    { id: 'summary', label: 'Summary' },
    { id: 'timeline', label: 'Timeline' },
    { id: 'probe', label: 'Probe evidence' },
    { id: 'evidence', label: 'Evidence' },
    { id: 'raw-events', label: 'Raw events' }
  ];
  const rawEventColumns: TableColumn<DataItem>[] = [
    { key: 'signal', label: 'Signal', render: (event) => humanizeSignalType(getString(event, ['signal_type'], 'event')) },
    { key: 'producer', label: 'Source type', render: (event) => plainCodeLabel(getString(event, ['producer_kind'], ''), 'Untrusted or legacy') },
    { key: 'source', label: 'Source', render: (event) => getString(event, ['source'], '—') },
    { key: 'reference', label: 'Reference', render: (event) => <span className="mono small mono-hash">{getString(event, ['check_id', 'target_id'], '—')}</span> },
    { key: 'recorded', label: 'Recorded', render: (event) => formatDate(event.timestamp ?? event.created_at) },
    { key: 'event_id', label: 'Event id', render: (event) => <span className="mono small mono-hash">{getString(event, ['id'], '—')}</span> }
  ];

  return (
    <div className="content">
      <DetailPageHeader
        route="run-detail"
        eyebrow="Test run evidence"
        entityId={entityId}
        title={runTitle}
        actions={(
          <>
            <AnchorButton size="sm" variant="secondary" href="#runs">Test runs</AnchorButton>
            {getString(entity, ['scan_id'], '') ? (
              <AnchorButton size="sm" variant="secondary" href={buildDetailHref('scan-detail', getString(entity, ['scan_id'], ''))}>Open parent scan</AnchorButton>
            ) : null}
            {primaryFinding ? (
              <AnchorButton size="sm" variant="default" href={buildDetailHref('finding-detail', getString(primaryFinding, ['id'], ''))}>Open finding</AnchorButton>
            ) : null}
            {cancellable && canManageRun ? (
              <>
                <Button size="sm" variant="danger" loading={busy === `cancel-${entityId}`} disabled={busy !== ''} onClick={() => setConfirmCancelOpen(true)}>Cancel</Button>
                <Button size="sm" variant="ghost" loading={busy === `finalize-${entityId}`} disabled={busy !== ''} onClick={() => setConfirmFinalizeOpen(true)}>Finalize</Button>
              </>
            ) : null}
          </>
        )}
      />
      <PageContextSummary>
        <StatusBadge value={status} tone={runStatusBadgeTone(status)} fallback="pending" /> ·{' '}
        {explicitRunValidationMode ? formatStatusLabel(explicitRunValidationMode) : 'Validation mode not recorded'} ·{' '}
        <code>{entityId}</code>
      </PageContextSummary>
      {loading ? <DetailLoadingPlaceholder label="Loading run detail…" /> : null}
      <DetailStatusBanners loadError={loadError} error={error} message={message} successTone="neutral" />
      {runEventEvidenceUnavailable ? (
        <div className="form-banner error" role="alert">
          <strong>{runEventState.error || 'Run event evidence unavailable.'}</strong>{' '}
          Probe and correlation evidence cannot be evaluated until the run-events endpoint recovers.
        </div>
      ) : null}
      {!loading ? (
        <>
          <div className="metric-grid four">
            <MetricCard label="Target group" value={groupName} sub="Declared scope under test" icon={Target} tone="info" />
            <MetricCard label="Check" value={checkDisplayName(data.checks, runCheckId)} sub={getString(entity, ['vector_family'], 'check')} icon={FileCheck2} tone="muted" />
            <MetricCard label="Verdict" value={verdictDisplay} sub="External-only confidence" icon={ShieldCheck} tone={verdictValue ? verdictBadgeTone(verdictValue) : 'muted'} />
            <MetricCard label="Duration" value={formatRunDuration(entity)} sub={formatStatusLabel(status, 'pending')} icon={Activity} tone="muted" />
          </div>
          <Tabs value={tab} options={tabOptions} onChange={setTab} className="tabs-wrap" ariaLabel="Run detail sections"
            getTabId={(id) => `run-detail-sections-tab-${id}`}
            getPanelId={(id) => `run-detail-sections-panel-${id}`} />

          {tab === 'summary' ? (
            <div role="tabpanel" id="run-detail-sections-panel-summary" aria-labelledby="run-detail-sections-tab-summary" className="tab-panel"><>
              <div className="dash-grid">
                <Card>
                  <CardHeader>
                    <CardTitle>Verdict summary</CardTitle>
                    <CardDescription>Stored outcome plus only the trusted signed probe events loaded for this run.</CardDescription>
                  </CardHeader>
                  <CardContent className="stack-tight">
                    {runEventEvidenceLoading ? (
                      <DetailLoadingPlaceholder label="Loading run proof…" variant="compact" />
                    ) : runEventEvidenceUnavailable ? (
                      <p className="muted">Run proof is unavailable because the event log could not be loaded.</p>
                    ) : (
                      <TrafficPathPanel detail={entity} events={trustedEvidenceEvents} />
                    )}
                    <div className="kv-list">
                      <div><span>Stored verdict</span>{verdictValue ? <VerdictBadge value={verdictValue} tone={verdictBadgeTone(verdictValue)} /> : <strong>No result yet</strong>}</div>
                      <div><span>Trusted events</span><strong>{runEventEvidenceLoading || runEventEvidenceUnavailable ? '—' : trustedEvidenceEvents.length}</strong></div>
                    </div>
                  </CardContent>
                </Card>
                <Card>
                  <CardHeader>
                    <CardTitle>Run facts</CardTitle>
                    <CardDescription>Recorded identifiers, declared relationships, and lifecycle timestamps for this run.</CardDescription>
                  </CardHeader>
                  <CardContent className="kv-list">
                    <DetailKvMonoField label="Run ID" value={entityId} />
                    <div><span>Status</span><StatusBadge value={status} tone={runStatusBadgeTone(status)} fallback="pending" /></div>
                    <div><span>Check</span>{runCheckId ? <DetailEntityLink route="check-detail" id={runCheckId} label={checkDisplayName(data.checks, runCheckId)} /> : <strong>not recorded</strong>}</div>
                    <div><span>Target group</span>{groupId ? <DetailEntityLink route="target-group-detail" id={groupId} label={groupName} /> : <strong>not recorded</strong>}</div>
                    <div><span>Target</span>{runTargetId ? <DetailEntityLink route="target-detail" id={runTargetId} /> : <strong>not recorded</strong>}</div>
                    <div><span>Policy</span>{runPolicyId ? <DetailEntityLink route="policy-detail" id={runPolicyId} label="Scheduled policy" /> : <strong>not scheduled by a recorded policy</strong>}</div>
                    <div><span>Validation mode</span><strong>{explicitRunValidationMode ? formatStatusLabel(explicitRunValidationMode) : 'not recorded'}</strong></div>
                    <div><span>Created</span><strong>{formatDate(entity.created_at)}</strong></div>
                    <div><span>Started</span><strong>{formatDate(entity.started_at)}</strong></div>
                    <div><span>Completed</span><strong>{formatDate(getNestedString(entity, ['verdict', 'finalized_at'], '') || entity.completed_at)}</strong></div>
                    <div><span>Initiated by</span><strong>{getString(entity, ['initiated_by', 'created_by'], 'not recorded')}</strong></div>
                    {runNonceHash ? <DetailKvMonoField label="Correlation nonce hash" value={runNonceHash} /> : null}
                  </CardContent>
                </Card>
              </div>
              <Card>
                <CardHeader>
                  <CardTitle>Correlation matrix</CardTitle>
                  <CardDescription>
                    External-only validation: signed outside probe evidence supports edge observations for this run. Verdicts report external-only confidence.
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  {runEventEvidenceLoading ? (
                    <DetailLoadingPlaceholder label="Loading correlation evidence…" variant="compact" />
                  ) : runEventEvidenceUnavailable ? (
                    <p className="muted">Correlation evidence unavailable because run event evidence could not be loaded.</p>
                  ) : (
                    <>
                      <VerdictExplanationPanel detail={entity} events={trustedEvidenceEvents} />
                      <TruthTablePanel detail={entity} />
                    </>
                  )}
                </CardContent>
              </Card>
            </></div>
          ) : null}

          {tab === 'timeline' ? (
            <div role="tabpanel" id="run-detail-sections-panel-timeline" aria-labelledby="run-detail-sections-tab-timeline" className="tab-panel"><Card>
              <CardHeader>
                <CardTitle>Timeline</CardTitle>
                <CardDescription>
                  Ordered run lifecycle and trusted event provenance{runPolicyId ? <span title={runPolicyId}> · scheduled policy</span> : null}.
                </CardDescription>
              </CardHeader>
              <CardContent className="stack-tight">
                <TimelinePanel items={milestoneTimeline} />
                {runEventState.status === 'loaded' ? (
                  <RunTimelineViz events={trustedEvidenceEvents} />
                ) : (
                  <p className="muted" role={runEventEvidenceLoading ? 'status' : undefined}>
                    {runEventEvidenceLoading ? 'Loading run event evidence…' : 'Timeline event evidence unavailable.'}
                  </p>
                )}
              </CardContent>
            </Card></div>
          ) : null}

          {tab === 'probe' ? (
            <div role="tabpanel" id="run-detail-sections-panel-probe" aria-labelledby="run-detail-sections-tab-probe" className="tab-panel"><div className="dash-grid">
              <Card>
                <CardHeader>
                  <CardTitle>Probe result</CardTitle>
                  <CardDescription>Signed outside observations loaded from this run event log.</CardDescription>
                </CardHeader>
                <CardContent>
                  {runEventEvidenceLoading ? (
                    <DetailLoadingPlaceholder label="Loading run event evidence…" variant="compact" />
                  ) : runEventEvidenceUnavailable ? (
                    <p className="muted">Probe event evidence unavailable.</p>
                  ) : probeEvents.length === 0 ? (
                    <EmptyState icon={Activity} title="No signed probe results recorded." body="A valid empty event log does not establish an outside observation." />
                  ) : (
                    <CapabilityProbeResultsPanel events={probeEvents} />
                  )}
                </CardContent>
              </Card>
            </div></div>
          ) : null}

          {tab === 'evidence' ? (
            <div role="tabpanel" id="run-detail-sections-panel-evidence" aria-labelledby="run-detail-sections-tab-evidence" className="tab-panel"><div className="dash-grid">
              <Card>
                <CardHeader>
                  <CardTitle>Evidence artifacts</CardTitle>
                  <CardDescription>Artifact records explicitly linked to this run. Open a record to inspect its returned digest and payload metadata.</CardDescription>
                </CardHeader>
                <CardContent>
                  {relatedEvidence.length === 0 ? (
                    <EmptyState icon={FileCheck2} title="No linked evidence records." body="No evidence artifact in the loaded vault data identifies this run." actionLabel="Open evidence vault" actionHref="#evidence" />
                  ) : (
                    <div className="kv-list">
                      {relatedEvidence.map((item) => {
                        const evidenceId = getString(item, ['id', 'evidence_id'], '');
                        const evidenceLabel = getString(item, ['label', 'kind', 'signal_type'], 'evidence');
                        const digest = getString(item, ['content_sha256', 'custody_digest'], '');
                        return (
                          <div key={evidenceId}>
                            <span>{evidenceLabel}</span>
                            <strong>
                              <DetailEntityLink route="evidence-detail" id={evidenceId} label={evidenceLabel} />
                              {digest ? <span className="muted small"> · <code className="mono-hash">{digest}</code></span> : null}
                            </strong>
                          </div>
                        );
                      })}
                    </div>
                  )}
                </CardContent>
              </Card>
              <Card>
                <CardHeader>
                  <CardTitle>Linked findings</CardTitle>
                  <CardDescription>Decisions whose test_run_id exactly matches this run.</CardDescription>
                </CardHeader>
                <CardContent>
                  {relatedFindings.length === 0 ? (
                    <EmptyState icon={TriangleAlert} title="No linked findings." body="No loaded finding record identifies this test run." actionLabel="Open findings" actionHref="#findings" />
                  ) : (
                    <div className="kv-list">
                      {relatedFindings.map((finding) => {
                        const findingId = getString(finding, ['id'], '');
                        return (
                          <div key={findingId}>
                            <span>{plainFindingTitle(finding, data.targets, data.checks)}</span>
                            <strong>
                              <DetailEntityLink route="finding-detail" id={findingId} label={formatStatusLabel(findingStatus(finding))} />
                              {' · '}<StatusBadge value={getString(finding, ['severity'], 'unknown')} tone={findingSeverityBadgeTone(getString(finding, ['severity'], 'unknown'))} fallback="unknown" />
                            </strong>
                          </div>
                        );
                      })}
                    </div>
                  )}
                </CardContent>
              </Card>
            </div></div>
          ) : null}

          {tab === 'raw-events' ? (
            <div role="tabpanel" id="run-detail-sections-panel-raw-events" aria-labelledby="run-detail-sections-tab-raw-events" className="tab-panel"><Card>
              <CardHeader>
                <CardTitle>Raw events</CardTitle>
                <CardDescription>Read-only event records for this run. Only signed probe events contribute to the proof panels.</CardDescription>
              </CardHeader>
              <CardContent>
                {runEventEvidenceLoading ? (
                  <DetailLoadingPlaceholder label="Loading raw run events…" variant="compact" />
                ) : runEventEvidenceUnavailable ? (
                  <p className="muted">Raw events are unavailable because the run-events endpoint failed or returned an invalid envelope.</p>
                ) : (
                  <DataTable
                    columns={rawEventColumns}
                    items={runEvents}
                    empty={<EmptyState icon={ClipboardList} title="No run events recorded." body="The run-events endpoint returned a valid empty items array for this run." />}
                  />
                )}
              </CardContent>
            </Card></div>
          ) : null}
        </>
      ) : null}
      <ConfirmModal
        open={canManageRun && confirmCancelOpen}
        title="Cancel this run in progress?"
        description={<p>Run {entityId} stops collecting and records no new verdict.</p>}
        confirmLabel="Cancel run"
        dismissLabel="Keep run"
        busy={busy === `cancel-${entityId}`}
        onCancel={() => setConfirmCancelOpen(false)}
        onConfirm={() => void confirmCancelRun()}
      />
      <ConfirmModal
        open={canManageRun && confirmFinalizeOpen}
        title="Force finalize this run now?"
        description={<p>This asks the backend to finalize using the evidence available at that time.</p>}
        confirmLabel="Force finalize"
        busy={busy === `finalize-${entityId}`}
        onCancel={() => setConfirmFinalizeOpen(false)}
        onConfirm={() => void confirmFinalizeRun()}
      />
    </div>
  );
}

const STAFF_ENTITLEMENT_FEATURES =['waf_posture', 'external_discovery', 'connectors', 'high_scale_program'] as const;

function TenantDetailView({
  entityId,
  detail,
  data,
  config,
  session,
  onRefresh,
  loading,
  loadError
}: {
  entityId: string;
  detail: DataItem | null;
  data: PortalData;
  config: PortalConfig;
  session: Session;
  onRefresh: () => Promise<void>;
  loading: boolean;
  loadError: string;
}) {
  const { confirm } = useConfirmModal();
  const [busy, setBusy] = useState('');
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');
  const [tab, setTab] = useState('overview');
  const [localDetail, setLocalDetail] = useState<DataItem | null>(detail);
  const [entitlementFeature, setEntitlementFeature] = useState<string>(STAFF_ENTITLEMENT_FEATURES[0]);
  const [entitlementEnabled, setEntitlementEnabled] = useState('true');

  useEffect(() => {
    setLocalDetail(detail);
  }, [detail]);

  const resolvedDetail = localDetail;
  const tenant = getNestedItem(resolvedDetail, ['tenant']) ?? resolvedDetail;
  const account = getNestedItem(resolvedDetail, ['account']);
  const subscription = getNestedItem(resolvedDetail, ['subscription']);
  const users = getNestedArray(resolvedDetail, ['users']);
  const signupRequest = getNestedItem(resolvedDetail, ['signup_request']);
  const recentAudit = getNestedArray(resolvedDetail, ['recent_tenant_audit']);
  const relatedApprovals = data.internalApprovalRequests.filter(
    (item) => getString(item, ['tenant_id'], '') === entityId
  );
  const lifecycleState = getString(account, ['lifecycle_state'], 'active');
  // MRR sourced from the subscription/account billing payload when present (graceful — no fabricated dollar figure).
  const mrrValue = getString(subscription, ['mrr', 'monthly_recurring_revenue', 'amount'], '')
    || getString(account, ['mrr', 'monthly_recurring_revenue'], '');

  const effectiveEntitlements = getNestedItem(subscription, ['effective_entitlements']);

  async function reloadTenantDetail() {
    const tenantPayload = await requestJson(config, session, `/internal/admin/tenants/${encodeURIComponent(entityId)}`);
    setLocalDetail(tenantPayload as DataItem);
  }

  async function runStaffAction<T>(label: string, action: () => Promise<T>, success: string) {
    setBusy(label);
    setError('');
    setMessage('');
    try {
      const result = await action();
      setMessage(success);
      await reloadTenantDetail();
      await onRefresh();
      return result;
    } catch (err) {
      setError(apiErrorMessage(err, 'Staff action failed.'));
      return null;
    } finally {
      setBusy('');
    }
  }

  async function patchLifecycle(nextState: string) {
    const impact = nextState === 'suspended'
      ? 'Suspend this tenant? Users will lose access until it is reactivated.'
      : 'Activate this tenant? Users will regain access to this tenant.';
    if (!await confirm({ title: 'Update tenant lifecycle', description: impact, confirmLabel: 'Apply lifecycle change' })) return;
    await runStaffAction(`lifecycle-${entityId}-${nextState}`, () => requestJson(config, session, `/internal/admin/tenants/${encodeURIComponent(entityId)}`, {
      method: 'PATCH',
      body: { lifecycle_state: nextState, reason: `Lifecycle set to ${nextState} from tenant detail.` }
    }), `Tenant lifecycle updated to ${nextState}.`);
  }

  async function patchSupportOwner(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const owner = String(new FormData(event.currentTarget).get('support_owner') ?? '').trim();
    if (!owner) return;
    await runStaffAction(`support-owner-${entityId}`, () => requestJson(config, session, `/internal/admin/tenants/${encodeURIComponent(entityId)}`, {
      method: 'PATCH',
      body: { support_owner: owner, reason: 'Support owner updated from tenant detail.' }
    }), 'Support owner updated.');
  }

  async function grantEntitlement(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const feature = String(form.get('feature') ?? '').trim();
    const enabled = String(form.get('enabled') ?? 'true') === 'true';
    const reason = String(form.get('reason') ?? '').trim();
    if (!feature) return;
    if (!await confirm({
      title: `${enabled ? 'Grant' : 'Revoke'} tenant entitlement`,
      description: `${enabled ? 'Grant' : 'Revoke'} entitlement "${feature}" for this tenant? This changes product access immediately.`,
      confirmLabel: `${enabled ? 'Grant' : 'Revoke'} entitlement`,
      confirmTone: enabled ? 'default' : 'danger'
    })) return;
    await runStaffAction(`entitlement-${entityId}-${feature}`, () => requestJson(config, session, `/internal/admin/tenants/${encodeURIComponent(entityId)}/entitlements`, {
      method: 'POST',
      body: { feature, enabled, reason: reason || `Entitlement ${enabled ? 'granted' : 'revoked'} from tenant detail.` }
    }), `${feature} entitlement ${enabled ? 'granted' : 'revoked'}.`);
  }

  async function resendInvite(userId: string) {
    await runStaffAction(`resend-${entityId}-${userId}`, () => requestJson(config, session, `/internal/admin/tenants/${encodeURIComponent(entityId)}/users/${encodeURIComponent(userId)}/resend-invite`, {
      method: 'POST',
      body: {}
    }), 'Invite resend recorded.');
  }

  async function disableUser(userId: string) {
    if (!await confirm({ title: 'Disable tenant user', description: 'Disable this user? They will lose access to this tenant until re-enabled by staff.', confirmLabel: 'Disable user' })) return;
    await runStaffAction(`disable-${entityId}-${userId}`, () => requestJson(config, session, `/internal/admin/tenants/${encodeURIComponent(entityId)}/users/${encodeURIComponent(userId)}/disable`, {
      method: 'POST',
      body: { reason: 'Disabled from tenant detail.' }
    }), 'User disabled.');
  }

  const userColumns: TableColumn<DataItem>[] = [
    { key: 'email', label: 'Email', render: (item) => getString(item, ['email']) },
    { key: 'role', label: 'Role', render: (item) => <Badge tone="muted">{getString(item, ['role'])}</Badge> },
    { key: 'status', label: 'Status', render: (item) => <Badge tone={getString(item, ['status']) === 'active' ? 'success' : 'warn'}>{getString(item, ['status'])}</Badge> },
    {
      key: 'actions',
      label: 'Actions',
      render: (item) => {
        const userId = getString(item, ['id'], '');
        if (getString(item, ['status']) === 'disabled') return '—';
        // The resend endpoint is an owner-invite resend (resendOwnerInvite matches role=owner in both
        // runtimes); offering it on other rows always failed with a misleading "record no longer exists".
        const canResend = getString(item, ['role']).toLowerCase() === 'owner';
        return (
          <div className="row-actions">
            {canResend ? <Button size="sm" variant="ghost" disabled={busy !== ''} onClick={() => void resendInvite(userId)}>Resend invite</Button> : null}
            <Button size="sm" variant="danger" disabled={busy !== ''} onClick={() => void disableUser(userId)}>Disable</Button>
          </div>
        );
      }
    }
  ];

  const approvalColumns: TableColumn<DataItem>[] = [
    { key: 'kind', label: 'Kind', render: (item) => getString(item, ['kind']) },
    { key: 'state', label: 'State', render: (item) => <Badge tone="warn">{getString(item, ['state'])}</Badge> },
    { key: 'created', label: 'Created', render: (item) => formatDate(item.created_at) }
  ];

  const auditColumns: TableColumn<DataItem>[] = [
    { key: 'action', label: 'Action', render: (item) => getString(item, ['action']) },
    { key: 'actor', label: 'Actor', render: (item) => getString(item, ['actor_user_id', 'staff_id'], '—') },
    { key: 'resource', label: 'Resource', render: (item) => `${getString(item, ['resource_type'])}:${getString(item, ['resource_id'], '—')}` },
    { key: 'created', label: 'Created', render: (item) => formatDate(item.created_at) }
  ];

  const tenantTitle = getString(tenant, ['name'], entityId);

  return (
    <div className="content">
      <DetailPageHeader
        route="tenant-detail"
        eyebrow="Staff tenant operations"
        entityId={entityId}
        title={tenantTitle}
        actions={(
          <>
            <AnchorButton size="sm" variant="secondary" href="#admin">Staff admin</AnchorButton>
            {lifecycleState !== 'active' ? (
              <Button size="sm" variant="secondary" disabled={busy !== ''} onClick={() => void patchLifecycle('active')}>Activate</Button>
            ) : (
              <Button size="sm" variant="danger" disabled={busy !== ''} onClick={() => void patchLifecycle('suspended')}>Suspend</Button>
            )}
          </>
        )}
      />
      <PageContextSummary>
        <StatusBadge value={lifecycleState} tone={lifecycleBadgeTone(lifecycleState)} /> · plan {getString(subscription, ['plan_id'], '—')} ·{' '}
        <span className="tabular-nums">{users.length}</span> users ·{' '}
        <span className="tabular-nums">{recentAudit.length}</span> recent audit events
      </PageContextSummary>
      {loading ? <DetailLoadingPlaceholder label="Loading tenant detail…" /> : null}
      <DetailStatusBanners loadError={loadError} error={error} message={message} mode="combined" />
      {!loading ? (
        <>
          <div className="metric-grid three">
            <MetricCard label="Lifecycle" value={formatStatusLabel(lifecycleState, 'active')} sub="Staff account state" icon={ShieldCheck} tone={lifecycleState === 'active' ? 'success' : 'warn'} />
            <MetricCard label="Plan" value={getString(subscription, ['plan_id'], '—')} sub={formatStatusLabel(getString(subscription, ['status'], 'not recorded'))} icon={FileText} tone="muted" />
            <MetricCard label="Users" value={users.length} sub="Tenant-scoped identities" icon={Users} tone="info" />
          </div>
          <Tabs
            value={tab}
            options={[
              { id: 'overview', label: 'Overview' },
              { id: 'billing', label: 'Billing & access' },
              { id: 'users', label: 'Users' },
              { id: 'audit', label: 'Audit' }
            ]}
            onChange={setTab}
            className="tabs-wrap"
            ariaLabel="Tenant detail sections"
            getTabId={(id) => `tenant-detail-sections-tab-${id}`}
            getPanelId={(id) => `tenant-detail-sections-panel-${id}`}
          />

          {tab === 'overview' ? (
            <div role="tabpanel" id="tenant-detail-sections-panel-overview" aria-labelledby="tenant-detail-sections-tab-overview" className="tab-panel"><>
              <div className="dash-grid">
                <Card>
                  <CardHeader>
                    <CardTitle>Account facts</CardTitle>
                    <CardDescription>Tenant identity, lifecycle, residency, and support ownership recorded by staff administration.</CardDescription>
                  </CardHeader>
                  <CardContent className="kv-list">
                    <div><span>Name</span><strong>{getString(tenant, ['name'])}</strong></div>
                    <DetailKvMonoField label="Tenant ID" value={entityId} />
                    <div><span>Lifecycle</span><StatusBadge value={lifecycleState} tone={lifecycleBadgeTone(lifecycleState)} /></div>
                    <div><span>Region</span><strong>{getString(account, ['region'], 'not recorded')}</strong></div>
                    <div><span>Support owner</span><strong>{getString(account, ['support_owner'], 'unassigned')}</strong></div>
                    <div><span>Created</span><strong>{formatDate(tenant?.created_at)}</strong></div>
                    <div><span>Updated</span><strong>{formatDate(tenant?.updated_at ?? account?.updated_at)}</strong></div>
                  </CardContent>
                </Card>
                <Card>
                  <CardHeader>
                    <CardTitle>Provisioning relationship</CardTitle>
                    <CardDescription>Signup request and internal approval records explicitly scoped to this tenant.</CardDescription>
                  </CardHeader>
                  <CardContent className="stack-tight">
                    {signupRequest ? (
                      <div className="kv-list">
                        <DetailKvMonoField label="Signup request" value={getString(signupRequest, ['id'], 'not returned')} />
                        <div><span>Signup state</span><StatusBadge value={getString(signupRequest, ['state'], 'recorded')} tone={signupRequestStateTone(getString(signupRequest, ['state']))} fallback="recorded" /></div>
                      </div>
                    ) : (
                      <p className="muted">No signup request is linked to this tenant. Tenants provisioned outside the signup queue may not have one.</p>
                    )}
                    <DataTable
                      columns={approvalColumns}
                      items={relatedApprovals}
                      empty={<EmptyState icon={ShieldCheck} title="No tenant approval requests." body="No loaded internal approval record identifies this tenant." />}
                    />
                  </CardContent>
                </Card>
              </div>
              <Card>
                <CardHeader>
                  <CardTitle>Support ownership</CardTitle>
                  <CardDescription>Assign the customer support owner. Every change is recorded in the administration audit trail.</CardDescription>
                </CardHeader>
                <CardContent>
                  <form className="product-form" onSubmit={patchSupportOwner}>
                    <label className="full"><span>Support owner</span><input name="support_owner" defaultValue={getString(account, ['support_owner'], '')} placeholder="owner@customer.example" required /></label>
                    <div className="form-actions full"><Button type="submit" loading={busy === `support-owner-${entityId}`} disabled={busy !== ''}>Save support owner</Button></div>
                  </form>
                </CardContent>
              </Card>
            </></div>
          ) : null}

          {tab === 'billing' ? (
            <div role="tabpanel" id="tenant-detail-sections-panel-billing" aria-labelledby="tenant-detail-sections-tab-billing" className="tab-panel"><>
              <div className="dash-grid">
                <Card>
                  <CardHeader>
                    <CardTitle>Subscription facts</CardTitle>
                    <CardDescription>Recorded plan and billing fields; missing values remain unavailable.</CardDescription>
                  </CardHeader>
                  <CardContent className="kv-list">
                    <div><span>Plan</span><strong>{getString(subscription, ['plan_id'], 'not recorded')}</strong></div>
                    <div><span>Status</span><StatusBadge value={getString(subscription, ['status'], 'not recorded')} tone={subscriptionStatusBadgeTone(getString(subscription, ['status'], ''))} fallback="not recorded" /></div>
                    <div><span>MRR</span><strong>{mrrValue || 'not returned'}</strong></div>
                    <div><span>Effective from</span><strong>{formatDate(subscription?.effective_from ?? subscription?.created_at)}</strong></div>
                  </CardContent>
                </Card>
                <Card>
                  <CardHeader>
                    <CardTitle>Effective entitlements</CardTitle>
                    <CardDescription>Feature access recorded for this subscription.</CardDescription>
                  </CardHeader>
                  <CardContent className="kv-list">
                    {effectiveEntitlements ? STAFF_ENTITLEMENT_FEATURES.map((feature) => (
                      <div key={feature}>
                        <span>{STAFF_ENTITLEMENT_LABELS[feature] ?? feature}</span>
                        <StatusBadge
                          value={effectiveEntitlements[feature] === true ? 'enabled' : 'disabled'}
                          tone={effectiveEntitlements[feature] === true ? 'success' : 'muted'}
                        />
                      </div>
                    )) : <p className="muted">No effective_entitlements object was returned.</p>}
                  </CardContent>
                </Card>
              </div>
              <Card>
                <CardHeader>
                  <CardTitle>Entitlement decision</CardTitle>
                  <CardDescription>Grant or revoke one feature with an explicit reason. Product access changes immediately.</CardDescription>
                </CardHeader>
                <CardContent>
                  {!subscription ? <div className="form-banner neutral" role="status">No subscription record is configured for this tenant.</div> : null}
                  <form className="product-form" onSubmit={grantEntitlement}>
                    <Select
                      label="Feature"
                      name="feature"
                      value={entitlementFeature}
                      onChange={setEntitlementFeature}
                      options={STAFF_ENTITLEMENT_FEATURES.map((feature) => ({
                        value: feature,
                        label: STAFF_ENTITLEMENT_LABELS[feature] ?? feature
                      }))}
                    />
                    <Select
                      label="Action"
                      name="enabled"
                      value={entitlementEnabled}
                      onChange={setEntitlementEnabled}
                      options={[
                        { value: 'true', label: 'Grant / enable' },
                        { value: 'false', label: 'Revoke / disable' }
                      ]}
                    />
                    <label className="full"><span>Reason</span><input name="reason" placeholder="Verified plan exception" required /></label>
                    <div className="form-actions full"><Button type="submit" disabled={busy !== ''}>Apply entitlement</Button></div>
                  </form>
                </CardContent>
              </Card>
            </></div>
          ) : null}

          {tab === 'users' ? (
            <div role="tabpanel" id="tenant-detail-sections-panel-users" aria-labelledby="tenant-detail-sections-tab-users" className="tab-panel"><Card>
              <CardHeader>
                <CardTitle>Tenant users</CardTitle>
                <CardDescription>Recorded owner and member identities. Resend and disable actions remain staff-gated.</CardDescription>
              </CardHeader>
              <CardContent>
                <DataTable columns={userColumns} items={users} empty={<EmptyState icon={Users} title="No tenant users returned." body="No user record was present in this tenant detail response." />} />
              </CardContent>
            </Card></div>
          ) : null}

          {tab === 'audit' ? (
            <div role="tabpanel" id="tenant-detail-sections-panel-audit" aria-labelledby="tenant-detail-sections-tab-audit" className="tab-panel"><Card>
              <CardHeader>
                <CardTitle>Internal audit</CardTitle>
                <CardDescription>Recent audit entries for this tenant.</CardDescription>
              </CardHeader>
              <CardContent>
                <DataTable columns={auditColumns} items={recentAudit} empty={<EmptyState icon={FileCheck2} title="No tenant audit entries returned." body="No recent_tenant_audit records were present in this response." />} />
              </CardContent>
            </Card></div>
          ) : null}
        </>
      ) : null}
    </div>
  );
}


function EvidenceDetailView({
  data,
  config,
  session
}: {
  data: PortalData;
  config: PortalConfig;
  session: Session;
}) {
  const entityId = getRouteEntityId('');
  const evidenceList = data.evidence;
  const initialFallback = evidenceList.find((item) => getString(item, ['id', 'evidence_id'], '') === entityId) ?? null;
  const [entity, setEntity] = useState<DataItem | null>(initialFallback);
  const [loading, setLoading] = useState(false);
  const [loadError, setLoadError] = useState('');
  const [loadErrorKind, setLoadErrorKind] = useState<'' | 'not_found' | 'denied' | 'unavailable'>('');
  const [reloadTick, setReloadTick] = useState(0);
  const [localDigest, setLocalDigest] = useState<{ value: string; at: string } | null>(null);
  const [integrityState, setIntegrityState] = useState<{ status: 'loading' | 'ready' | 'denied' | 'unavailable'; value: string; verifiedAt: string; method: string }>({ status: 'loading', value: '', verifiedAt: '', method: '' });
  const [integrityReload, setIntegrityReload] = useState(0);

  useEffect(() => {
    if (!entityId) return undefined;
    let cancelled = false;
    setIntegrityState({ status: 'loading', value: '', verifiedAt: '', method: '' });
    requestJson(config, session, `/v1/evidence-context?entry=artifact&evidence_id=${encodeURIComponent(entityId)}`)
      .then((payload) => {
        if (cancelled) return;
        const integrity = getNestedItem(payload as DataItem, ['primary', 'integrity']);
        setIntegrityState({
          status: 'ready',
          value: getString(integrity ?? {}, ['status'], 'not_recorded'),
          verifiedAt: getString(integrity ?? {}, ['verified_at'], ''),
          method: getString(integrity ?? {}, ['method'], '')
        });
      })
      .catch((err) => {
        if (cancelled) return;
        const status = Number((err as { status?: unknown })?.status ?? 0);
        setIntegrityState({ status: status === 403 ? 'denied' : 'unavailable', value: '', verifiedAt: '', method: '' });
      });
    return () => { cancelled = true; };
  }, [entityId, config, session, integrityReload]);
  const [busy, setBusy] = useState('');
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');

  useEffect(() => {
    if (!entityId) {
      setEntity(null);
      return;
    }
    let cancelled = false;
    const localFallback = evidenceList.find((item) => getString(item, ['id', 'evidence_id'], '') === entityId) ?? null;
    setEntity(localFallback);
    setLoading(true);
    setLoadError('');
    setLoadErrorKind('');
    setLocalDigest(null);
    requestJson(config, session, `/v1/evidence/${encodeURIComponent(entityId)}`)
      .then((payload) => {
        if (cancelled) return;
        if (payload && typeof payload === 'object' && !Array.isArray(payload)) {
          setEntity(payload as DataItem);
        }
      })
      .catch((err) => {
        if (cancelled) return;
        const text = err instanceof Error ? err.message : 'Evidence artifact unavailable.';
        const status = Number((err as { status?: unknown })?.status ?? 0);
        setLoadErrorKind(status === 404 || /not.?found/i.test(text) ? 'not_found' : status === 403 || /forbidden|permission/i.test(text) ? 'denied' : 'unavailable');
        setLoadError(text);
        setEntity(localFallback);
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [entityId, config, session, evidenceList, reloadTick]);

  if (!entityId) {
    return (
      <div className="content">
        <DetailPageHeader
          route="evidence-detail"
          eyebrow="Validation · evidence artifact"
          entityId=""
          title="Evidence artifact"
        />
        <EmptyState
          icon={ShieldCheck}
          title="No evidence artifact selected."
          body="Open an artifact from a run's evidence chain or a finding's evidence bundle."
          actionLabel="Open findings"
          actionHref="#findings"
        />
      </div>
    );
  }

  if (!entity && loading) {
    return (
      <div className="content">
        <DetailPageIntro route="evidence-detail" eyebrow="Validation · evidence artifact" />
        <DetailLoadingPlaceholder label="Loading evidence artifact…" />
      </div>
    );
  }

  if (!entity) {
    return (
      <div className="content">
        <DetailPageHeader
          route="evidence-detail"
          eyebrow="Validation · evidence artifact"
          entityId={entityId}
          title="Evidence artifact"
        />
        {loadErrorKind === 'unavailable' ? (
          <EmptyState
            icon={TriangleAlert}
            title="Evidence artifact unavailable."
            body={`${loadError} The artifact may still exist; this is a read failure, not missing evidence.`}
            actionLabel="Retry"
            onAction={() => setReloadTick((count) => count + 1)}
          />
        ) : loadErrorKind === 'denied' ? (
          <EmptyState
            icon={ShieldCheck}
            title="Evidence access required."
            body="Your role cannot read evidence artifacts (evidence:read). No alternative source is used."
            actionLabel="Open findings"
            actionHref="#findings"
          />
        ) : (
          <EmptyState
            icon={ShieldCheck}
            title="Evidence artifact not found."
            body={`No artifact with ID ${entityId} is visible in this workspace. It may have expired under retention or belong to another tenant.`}
            actionLabel="Open findings"
            actionHref="#findings"
          />
        )}
      </div>
    );
  }

  const artifactId = getString(entity, ['artifact_id', 'id', 'evidence_id'], entityId);
  const kind = getString(entity, ['kind', 'label', 'signal_type'], '');
  const producedBy = getString(entity, ['produced_by', 'source'], getNestedString(entity, ['metadata', 'source'], ''));
  const runId = getString(entity, ['test_run_id', 'run_id'], '');
  const sizeLabel = formatEvidenceSize(entity);
  const sealedAtRaw = getString(entity, ['sealed_at'], '');
  const recordedAtRaw = getString(entity, ['created_at', 'timestamp'], '');
  const sha256 = getString(entity, ['content_sha256', 'sha256', 'custody_digest'], getNestedString(entity, ['metadata', 'sha256'], ''));
  const chainPosition = getString(entity, ['chain_position'], '');
  const bundle = getString(entity, ['bundle', 'bundle_id'], '');
  const bundleSha256 = getString(entity, ['bundle_sha256'], '');

  const findingId = (() => {
    const direct = getString(entity, ['finding_id'], '');
    if (direct) return direct;
    const byEvidence = data.findings.find((finding) => {
      const ids = Array.isArray(finding.evidence_ids) ? (finding.evidence_ids as unknown[]).map(String) : [];
      return ids.includes(artifactId) || ids.includes(entityId);
    });
    if (byEvidence) return getString(byEvidence, ['id'], '');
    return '';
  })();

  const displayedPayload = getNestedItem(entity, ['payload']) ?? getNestedItem(entity, ['content']) ?? getNestedItem(entity, ['metadata']);
  const payloadSource = getNestedItem(entity, ['payload']) ? 'payload' : getNestedItem(entity, ['content']) ? 'content' : getNestedItem(entity, ['metadata']) ? 'metadata' : '';
  const payloadJson = displayedPayload && Object.keys(displayedPayload).length > 0 ? JSON.stringify(displayedPayload, null, 2) : '';

  const serverVerified = integrityState.status === 'ready' && integrityState.value === 'verified';
  const serverVerificationLabel = integrityState.status === 'loading'
    ? 'Checking recorded verification…'
    : integrityState.status === 'denied'
      ? 'Not visible to your role'
      : integrityState.status === 'unavailable'
        ? 'Verification status unavailable'
        : integrityState.value === 'verified'
          ? `Verified by the server${integrityState.verifiedAt ? ` ${formatDate(integrityState.verifiedAt)}` : ''}${integrityState.method ? ` · ${integrityState.method}` : ''}`
          : integrityState.value === 'not_verified'
            ? 'Not verified: no authoritative verification succeeded'
            : integrityState.value === 'recorded_digest'
              ? 'Not verified (recorded hash only)'
              : 'Not verified (no hash or verification recorded)';

  const artifactRecord = evidenceCodeBlock([
    ['artifact_id', artifactId],
    ['kind', kind],
    ['produced_by', producedBy],
    ['run', runId],
    ['finding', findingId],
    ['size', sizeLabel],
    ['recorded_at', recordedAtRaw ? formatDate(recordedAtRaw) : ''],
    ['sealed_at', sealedAtRaw ? formatDate(sealedAtRaw) : ''],
  ]);

  const custodyRecord = evidenceCodeBlock([
    ['sha256', sha256],
    ['digest_kind', sha256 ? CUSTODY_CONTENT_CANONICALIZATION : ''],
    ['chain_position', chainPosition],
    ['bundle', bundle],
    ['bundle_sha256', bundleSha256]
  ]);

  function buildArtifactExportPayload(): Record<string, unknown> {
    const payload: Record<string, unknown> = {
      exported_at: new Date().toISOString(),
      evidence_ids: [artifactId],
      artifact_id: artifactId
    };
    if (kind) payload.kind = kind;
    if (producedBy) payload.produced_by = producedBy;
    if (runId) payload.run = runId;
    if (findingId) payload.finding = findingId;
    if (sizeLabel) payload.size = sizeLabel;
    if (recordedAtRaw) payload.recorded_at = recordedAtRaw;
    if (sealedAtRaw) payload.sealed_at = sealedAtRaw;
    if (sha256) payload.content_sha256 = sha256;
    if (chainPosition) payload.chain_position = chainPosition;
    if (bundle) payload.bundle = bundle;
    if (bundleSha256) payload.bundle_sha256 = bundleSha256;
    if (displayedPayload && Object.keys(displayedPayload).length > 0) payload.displayed_json = displayedPayload;
    if (payloadSource) payload.displayed_json_source = payloadSource;
    return payload;
  }

  async function recomputeDigest() {
    setBusy('verify');
    setError('');
    setMessage('');
    try {
      if (!displayedPayload || Object.keys(displayedPayload).length === 0) {
        setError('No displayed sealed JSON is available for local digest calculation. No server verification request was made.');
        return;
      }
      const manifest = await buildEvidenceCustodyManifest(displayedPayload, session.tenant_id);
      const recomputed = getString(manifest as DataItem, ['content_sha256'], '');
      if (recomputed) {
        setLocalDigest({ value: recomputed, at: new Date().toISOString() });
        setMessage(`Locally computed ${CUSTODY_CONTENT_CANONICALIZATION} digest over the JSON shown on this page only. The recorded artifact digest may cover different sealed bytes, so no comparison or server verification was performed.`);
      } else {
        setError('No displayed sealed contents are available for local digest recomputation. No server verification request was made.');
      }
    } catch (err) {
      setError(apiErrorMessage(err, 'Digest recomputation failed.'));
    } finally {
      setBusy('');
    }
  }

  async function exportArtifact() {
    setBusy('export');
    setError('');
    setMessage('');
    try {
      const payload = buildArtifactExportPayload();
      const custody = await buildEvidenceCustodyManifest(payload, session.tenant_id);
      triggerJsonDownload(`evidence-${artifactId}.json`, { payload, custody });
      setMessage('Evidence artifact exported with a locally generated manifest over the downloaded JSON.');
    } catch (err) {
      setError(apiErrorMessage(err, 'Export failed.'));
    } finally {
      setBusy('');
    }
  }

  return (
    <div className="content">
      <DetailPageHeader
        route="evidence-detail"
        eyebrow="Validation · evidence artifact"
        entityId={artifactId}
        title={plainCodeLabel(kind, 'Evidence artifact')}
        actions={(
          <>
            {findingId ? (
              <AnchorButton size="sm" variant="secondary" href={buildDetailHref('finding-detail', findingId)}>Back to finding</AnchorButton>
            ) : null}
            <Button size="sm" variant="ghost" loading={busy === 'verify'} disabled={busy !== '' || !payloadJson} onClick={() => void recomputeDigest()}>Compute local digest</Button>
            <Button size="sm" variant="secondary" loading={busy === 'export'} disabled={busy !== ''} onClick={() => void exportArtifact()}>Export artifact JSON</Button>
          </>
        )}
      />
      <CustomerPageStyles />
      <p className="muted small">One recorded artifact. {findingId
        ? 'It is referenced by the finding linked above.'
        : data.findingsMeta && !data.findingsMeta.hasMore
          ? 'No finding references this artifact explicitly.'
          : `No finding among the ${formatNumber(data.findings.length)} newest loaded findings references this artifact; older findings were not checked.`}{runId ? ` Recorded by run ${runId}.` : ''}</p>
      {loading ? <DetailLoadingPlaceholder label="Refreshing evidence artifact…" variant="compact" /> : null}
      {loadError && entity ? (
        <div className="form-banner error row-actions" role="alert">
          <span>Refresh failed: {loadError} Showing the copy loaded earlier in this session.</span>
          <Button size="sm" variant="secondary" onClick={() => setReloadTick((count) => count + 1)}>Retry</Button>
        </div>
      ) : null}
      <DetailStatusBanners loadError="" error={error} message={message} />
      <Card>
        <CardHeader>
          <CardTitle>Integrity</CardTitle>
          <CardDescription>Each state is separate. A recorded hash alone does not prove custody.</CardDescription>
        </CardHeader>
        <CardContent className="kv-list">
          <div><span>Recorded hash</span><strong className="cp-mono-wrap">{sha256 || 'Not recorded'}</strong></div>
          <div><span>Locally computed (this page)</span><strong className="cp-mono-wrap">{localDigest ? `${localDigest.value} · ${formatDate(localDigest.at)}, over displayed JSON only` : 'Not computed'}</strong></div>
          <div>
            <span>Server verification</span>
            <strong>
              {serverVerificationLabel}
              {integrityState.status === 'unavailable' ? <> <button type="button" className="rf-link-button" onClick={() => setIntegrityReload((count) => count + 1)}>Retry</button></> : null}
            </strong>
          </div>
          {sealedAtRaw ? <div><span>Sealed</span><strong>{formatDate(sealedAtRaw)}</strong></div> : null}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Artifact</CardTitle>
          <CardDescription>Recorded fields only.</CardDescription>
        </CardHeader>
        <CardContent className="kv-list">
          <div><span>Kind</span><strong>{plainCodeLabel(kind, 'Not recorded')}</strong></div>
          <div><span>Recorded by run</span><strong className="cp-mono-wrap">{runId || 'Not recorded'}</strong></div>
          <div><span>Size</span><strong>{sizeLabel || 'Not recorded'}</strong></div>
          <div><span>Recorded</span><strong>{recordedAtRaw ? formatDate(recordedAtRaw) : 'Not recorded'}</strong></div>
        </CardContent>
      </Card>

      <div className="dash-grid">
        <Card>
          <CardHeader>
            <CardTitle>Artifact record</CardTitle>
            <CardDescription>Recorded artifact metadata. Absent fields are omitted rather than inferred.</CardDescription>
          </CardHeader>
          <CardContent>
            {artifactRecord ? (
              <DetailCodeBlock label="Artifact record">{artifactRecord}</DetailCodeBlock>
            ) : (
              <p className="muted">No artifact metadata recorded for this evidence id.</p>
            )}

          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>Supplied chain metadata &amp; digest</CardTitle>
            <CardDescription>Recorded chain and digest values are shown exactly; this panel does not independently verify them.</CardDescription>
          </CardHeader>
          <CardContent>
            {custodyRecord ? (
              <DetailCodeBlock label="Custody and digest">{custodyRecord}</DetailCodeBlock>
            ) : (
              <EmptyState icon={ShieldCheck} title="No custody digest recorded." body="This artifact has no sealed SHA-256 digest or bundle reference in the vault record." />
            )}
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Stored JSON preview</CardTitle>
          <CardDescription>{payloadSource ? `Technical ${payloadSource} record available.` : 'No payload, content, or metadata record is available.'}</CardDescription>
        </CardHeader>
        <CardContent>
          {payloadJson ? (
            <DetailCodeBlock label="Artifact JSON preview">{payloadJson}</DetailCodeBlock>
          ) : (
            <EmptyState icon={FileText} title="Metadata-only artifact." body="No payload or content is retained for this artifact, which is expected for metadata-only retention. This does not indicate corruption." />
          )}
        </CardContent>
      </Card>
    </div>
  );
}

function HighScaleDetailView({
  entity,
  entityId,
  data,
  config,
  session,
  onRefresh,
  loading,
  loadError
}: {
  entity: DataItem;
  entityId: string;
  data: PortalData;
  config: PortalConfig;
  session: Session;
  onRefresh: () => Promise<void>;
  loading: boolean;
  loadError: string;
}) {
  const [tab, setTab] = useState('overview');
  const [busy, setBusy] = useState('');
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');
  const [drafts, setDrafts] = useState<Record<string, AuthorizationArtifactDraft>>({});
  const [lastFailedUploadType, setLastFailedUploadType] = useState('');
  const tabOptions = [
    { id: 'overview', label: 'Overview' },
    { id: 'authorization', label: 'Authorization pack' },
    { id: 'lifecycle', label: 'Lifecycle' },
    { id: 'provider', label: 'Provider checklist' }
  ];
  const packStatus = getNestedItem(entity, ['authorization_pack_status']);
  const artifacts = Array.isArray(entity.artifacts) ? entity.artifacts as DataItem[] : [];
  const providerChecklist = Array.isArray(entity.provider_approval_checklist) ? entity.provider_approval_checklist as DataItem[] : [];
  const lifecycleTrail = buildLifecycleTimeline(entity);
  const targetGroup = data.targetGroups.find((group) => getString(group, ['id'], '') === getString(entity, ['target_group_id'], ''));
  const title = detailEntityTitle('queue-detail', entity, entityId);
  const requiredArtifactTypes = authorizationArtifactTypesForRequest(entity);
  const canWriteHighScale = sessionHasPermission(session, 'high_scale:write');

  function draftForType(type: string): AuthorizationArtifactDraft {
    return drafts[type] ?? { filename: '', content_sha256: '', custody_id: '' };
  }

  function updateDraft(type: string, field: keyof AuthorizationArtifactDraft, value: string) {
    setDrafts((current) => {
      const existing = current[type];
      return {
        ...current,
        [type]: {
          filename: existing?.filename ?? '',
          content_sha256: existing?.content_sha256 ?? '',
          custody_id: existing?.custody_id ?? '',
          [field]: value
        }
      };
    });
  }

  async function uploadAuthorizationArtifact(type: string) {
    if (!canWriteHighScale) return;
    const draft = draftForType(type);
    const filename = draft.filename.trim();
    if (!filename) {
      setError('Filename is required before upload.');
      setMessage('');
      return;
    }
    setBusy(`upload-${type}`);
    setError('');
    setMessage('');
    setLastFailedUploadType('');
    try {
      const contentSha256 = draft.content_sha256.trim();
      if (!contentSha256) {
        setError('A SHA-256 digest of the actual artifact bytes is required. This metadata form does not read or hash a local file.');
        return;
      }
      if (!/^[a-f0-9]{64}$/i.test(contentSha256)) {
        setError('Content digest must be exactly 64 hexadecimal characters.');
        return;
      }
      const body = buildMetadataArtifactUploadBody(entity, type, {
        filename,
        content_sha256: contentSha256,
        custody_id: draft.custody_id.trim() || undefined
      });
      await requestJson(config, session, `/v1/high-scale-requests/${encodeURIComponent(entityId)}/artifacts`, {
        method: 'POST',
        body
      });
      setMessage(`${authorizationArtifactTitle(type)} metadata uploaded.`);
      await onRefresh();
    } catch (err) {
      setLastFailedUploadType(type);
      setError(apiErrorMessage(err, 'Authorization artifact upload failed.'));
    } finally {
      setBusy('');
    }
  }

  const requestState = getString(entity, ['state'], 'submitted');
  const packOverall = getString(packStatus ?? {}, ['overall'], 'missing');
  const requestedWindowStart = getNestedString(entity, ['requested_window', 'window_start'], '');
  const requestedWindowEnd = getNestedString(entity, ['requested_window', 'window_end'], '');
  const requestedTimezone = getNestedString(entity, ['requested_window', 'timezone'], '');
  const scheduledWindowStart = getNestedString(entity, ['scheduled_window', 'window_start'], '');
  const scheduledWindowEnd = getNestedString(entity, ['scheduled_window', 'window_end'], '');
  const scopeHash = getString(entity, ['scope_hash'], '');
  const socApprovals = Array.isArray(entity.soc_approvals) ? entity.soc_approvals as DataItem[] : [];
  const adapterRecord = getNestedItem(entity, ['adapter']) ?? getNestedItem(entity, ['adapter_json']);
  const requestGates = [
    { label: 'Authorization pack accepted', pass: packOverall === 'accepted', detail: formatStatusLabel(packOverall, 'missing') },
    { label: 'Requested safe window recorded', pass: Boolean(requestedWindowStart && requestedWindowEnd), detail: requestedWindowStart && requestedWindowEnd ? `${formatDate(requestedWindowStart)} → ${formatDate(requestedWindowEnd)}` : 'window incomplete' },
    { label: 'Scope hash recorded', pass: Boolean(scopeHash), detail: scopeHash ? 'scope hash present' : 'not returned' },
    { label: 'SOC approval recorded', pass: socApprovals.length > 0, detail: `${socApprovals.length} approval record${socApprovals.length === 1 ? '' : 's'}` }
  ];

  return (
    <div className="content">
      <DetailPageHeader
        route="queue-detail"
        eyebrow="SOC-gated validation"
        entityId={entityId}
        title={title}
        actions={packOverall === 'accepted'
          ? <AnchorButton size="sm" variant="default" href="#runs">Open high-scale requests</AnchorButton>
          : <Button size="sm" variant="default" onClick={() => setTab('authorization')}>{canWriteHighScale ? 'Complete authorization pack' : 'View authorization pack'}</Button>}
      />
      <PageContextSummary>
        <StatusBadge value={requestState} tone={highScaleStateBadgeTone(requestState)} fallback="submitted" /> · pack{' '}
        <StatusBadge value={packOverall} tone={artifactReviewBadgeTone(packOverall)} fallback="missing" />
      </PageContextSummary>
      {loading ? <DetailLoadingPlaceholder label="Loading high-scale request…" /> : null}
      <DetailStatusBanners loadError={loadError} error={error} message={message}>
        {error && lastFailedUploadType && canWriteHighScale ? (
          <div className="row-actions">
            <Button size="sm" variant="secondary" loading={busy === `upload-${lastFailedUploadType}`} disabled={busy !== ''} onClick={() => void uploadAuthorizationArtifact(lastFailedUploadType)}>Retry artifact record</Button>
          </div>
        ) : null}
      </DetailStatusBanners>
      {!loading ? (
        <>
          <div className="metric-grid four">
            <MetricCard label="State" value={formatStatusLabel(requestState)} sub="Governed request lifecycle" icon={ShieldCheck} tone={highScaleStateBadgeTone(requestState) === 'danger' ? 'danger' : highScaleStateBadgeTone(requestState) === 'warn' ? 'warn' : highScaleStateBadgeTone(requestState) === 'success' ? 'success' : 'info'} />
            <MetricCard label="Authorization" value={formatStatusLabel(packOverall, 'missing')} sub={`${artifacts.length} artifact records`} icon={FileCheck2} tone={packOverall === 'accepted' ? 'success' : 'warn'} />
            <MetricCard label="Scope" value={getString(targetGroup ?? {}, ['name'], getString(entity, ['target_group_id'], '—'))} sub={scopeHash ? 'scope hash recorded' : 'scope hash not returned'} icon={Target} tone={scopeHash ? 'info' : 'muted'} />
            <MetricCard label="Window" value={requestedWindowStart ? formatDate(requestedWindowStart) : '—'} sub={requestedWindowEnd ? `through ${formatDate(requestedWindowEnd)}` : 'requested window incomplete'} icon={Activity} tone={requestedWindowStart && requestedWindowEnd ? 'info' : 'muted'} />
          </div>
          <Tabs value={tab} options={tabOptions} onChange={setTab} className="tabs-wrap" ariaLabel="High-scale request sections"
            getTabId={(id) => `high-scale-request-sections-tab-${id}`}
            getPanelId={(id) => `high-scale-request-sections-panel-${id}`} />

          {tab === 'overview' ? (
            <div role="tabpanel" id="high-scale-request-sections-panel-overview" aria-labelledby="high-scale-request-sections-tab-overview" className="tab-panel"><>
              <div className="dash-grid">
                <Card>
                  <CardHeader>
                    <CardTitle>Request facts</CardTitle>
                    <CardDescription>Recorded customer request, declared scope, safe window, and source details.</CardDescription>
                  </CardHeader>
                  <CardContent className="kv-list">
                    <div><span>Request</span><strong title={entityId}>{title}</strong></div>
                    <div><span>State</span><StatusBadge value={requestState} tone={highScaleStateBadgeTone(requestState)} fallback="submitted" /></div>
                    <div><span>Target group</span>{getString(entity, ['target_group_id'], '') ? <DetailEntityLink route="target-group-detail" id={getString(entity, ['target_group_id'], '')} label={getString(targetGroup ?? {}, ['name'], getString(entity, ['target_group_id']))} /> : <strong>not recorded</strong>}</div>
                    <div><span>Reason</span><strong>{getString(entity, ['reason'], 'not recorded')}</strong></div>
                    <div><span>Objective</span><strong>{getString(entity, ['objective'], 'not recorded')}</strong></div>
                    <div><span>Requested by</span><strong>{getString(entity, ['created_by', 'requested_by'], 'not recorded')}</strong></div>
                    <div><span>Created</span><strong>{formatDate(entity.created_at)}</strong></div>
                    <div><span>Requested window</span><strong>{requestedWindowStart && requestedWindowEnd ? `${formatDate(requestedWindowStart)} → ${formatDate(requestedWindowEnd)}` : 'not fully recorded'}</strong></div>
                    <div><span>Timezone</span><strong>{requestedTimezone || 'not recorded'}</strong></div>
                    <div><span>Scheduled window</span><strong>{scheduledWindowStart && scheduledWindowEnd ? `${formatDate(scheduledWindowStart)} → ${formatDate(scheduledWindowEnd)}` : 'not scheduled'}</strong></div>
                    {scopeHash ? <div><span>Scope hash</span><strong title={scopeHash}>Recorded</strong></div> : null}
                  </CardContent>
                </Card>
                <Card>
                  <CardHeader>
                    <CardTitle>Gate chain</CardTitle>
                    <CardDescription>Recorded prerequisites. SOC still revalidates scope, window, and authorization before execution.</CardDescription>
                  </CardHeader>
                  <CardContent>
                    <ul className="placement-gates" aria-label="High-scale request gates">
                      {requestGates.map((gate) => (
                        <li key={gate.label}>
                          <ShieldCheck size={14} aria-hidden="true" />
                          <span>{gate.label}<span className="muted small"> · {plainInlineText(gate.detail)}</span></span>
                          <Badge tone={gate.pass ? 'success' : 'muted'}>{gate.pass ? 'recorded' : 'pending'}</Badge>
                        </li>
                      ))}
                    </ul>
                  </CardContent>
                </Card>
              </div>
              <Card>
                <CardHeader>
                  <CardTitle>Execution telemetry</CardTitle>
                  <CardDescription>Provider execution fields appear only when they were recorded for this request.</CardDescription>
                </CardHeader>
                <CardContent>
                  {adapterRecord ? (
                    <div className="kv-list">
                      <div><span>Adapter state</span><strong>{getString(adapterRecord, ['state'], 'not returned')}</strong></div>
                      <div><span>Traffic generated</span><strong>{getString(adapterRecord, ['traffic_generated'], 'not returned')}</strong></div>
                      <div><span>Recorded at</span><strong>{formatDate(adapterRecord.updated_at ?? adapterRecord.created_at)}</strong></div>
                    </div>
                  ) : (
                    <EmptyState icon={Activity} title="No execution telemetry returned." body="Provider state and traffic generation are not inferred from request lifecycle status." />
                  )}
                </CardContent>
              </Card>
            </></div>
          ) : null}

          {tab === 'authorization' ? (
            <div role="tabpanel" id="high-scale-request-sections-panel-authorization" aria-labelledby="high-scale-request-sections-tab-authorization" className="tab-panel"><Card>
              <CardHeader><CardTitle>Authorization artifacts</CardTitle><CardDescription>Record metadata references for SOC review. This form does not upload or hash local file bytes.</CardDescription></CardHeader>
              <CardContent className="stack-tight">
                <div className="artifact-upload-grid">
                  {requiredArtifactTypes.map((type) => {
                    const draft = draftForType(type);
                    const bestArtifact = bestArtifactForType(artifacts, type);
                    const requirement = packRequirementForType(packStatus, type);
                    const uploadBusy = busy === `upload-${type}`;
                    return (
                      <div key={type} className="artifact-upload-card">
                        <div className="artifact-upload-card__header">
                          <div>
                            <strong>{authorizationArtifactTitle(type)}</strong>
                            <p className="muted small">{authorizationArtifactPurpose(type)}</p>
                          </div>
                        </div>
                        <p className="muted small">{explainArtifactReviewStatus(type, requirement, bestArtifact)}</p>
                        <div className="product-form compact">
                          <label className="full">
                            <span>File name</span>
                            <input value={draft.filename} readOnly={!canWriteHighScale} placeholder={`${type}.pdf`} onChange={(event) => updateDraft(type, 'filename', event.target.value)} />
                          </label>
                          <label className="full">
                            <span>Content digest (SHA-256)</span>
                            <input value={draft.content_sha256} readOnly={!canWriteHighScale} required placeholder="Required — SHA-256 of the artifact bytes" onChange={(event) => updateDraft(type, 'content_sha256', event.target.value)} />
                          </label>
                          <label className="full">
                            <span>Custody record id</span>
                            <input value={draft.custody_id} readOnly={!canWriteHighScale} placeholder="Optional external custody reference" onChange={(event) => updateDraft(type, 'custody_id', event.target.value)} />
                          </label>
                          <div className="form-actions full">
                            {canWriteHighScale ? <Button size="sm" variant="secondary" loading={uploadBusy} disabled={busy !== ''} onClick={() => void uploadAuthorizationArtifact(type)}>Record artifact</Button> : <span className="muted">Read only</span>}
                          </div>
                        </div>
                      </div>
                    );
                  })}
                </div>
                <div className="artifact-upload-card__meta">
                  <strong>Recorded artifacts</strong>
                  {artifacts.length === 0 ? <p className="muted">No artifact records returned.</p> : (
                    <div className="kv-list">
                      {artifacts.map((artifact) => {
                        const type = getString(artifact, ['type']);
                        const artifactStatus = getString(artifact, ['status'], 'pending_review');
                        const digest = getString(artifact, ['content_sha256'], '');
                        return (
                          <div key={getString(artifact, ['id'], type)}>
                            <span>{authorizationArtifactTitle(type)}</span>
                            <strong>
                              <StatusBadge value={artifactStatus} tone={artifactReviewBadgeTone(artifactStatus)} fallback="pending_review" />
                              {digest ? <> · <code className="mono-hash">{digest}</code></> : null}
                            </strong>
                            <p className="muted small">{explainArtifactReviewStatus(type, packRequirementForType(packStatus, type), artifact)}</p>
                          </div>
                        );
                      })}
                    </div>
                  )}
                </div>
              </CardContent>
            </Card></div>
          ) : null}

          {tab === 'lifecycle' ? (
            <div role="tabpanel" id="high-scale-request-sections-panel-lifecycle" aria-labelledby="high-scale-request-sections-tab-lifecycle" className="tab-panel"><Card>
              <CardHeader><CardTitle>Lifecycle trail</CardTitle><CardDescription>Ordered transitions recorded for this request.</CardDescription></CardHeader>
              <CardContent><TimelinePanel items={lifecycleTrail.map((event) => ({ label: event.action, at: event.at }))} /></CardContent>
            </Card></div>
          ) : null}

          {tab === 'provider' ? (
            <div role="tabpanel" id="high-scale-request-sections-panel-provider" aria-labelledby="high-scale-request-sections-tab-provider" className="tab-panel"><Card>
              <CardHeader><CardTitle>Provider checklist</CardTitle><CardDescription>Provider requirements and review states recorded for this request; no live provider telemetry is inferred.</CardDescription></CardHeader>
              <CardContent>
                {providerChecklist.length === 0 ? <p className="muted">No provider checklist items returned.</p> : (
                  <div className="kv-list">
                    {providerChecklist.map((item, index) => (
                      <div key={getString(item, ['id'], String(index))}>
                        <span>{getString(item, ['label', 'provider_name', 'requirement'], 'Provider requirement')}</span>
                        <strong>
                          <StatusBadge value={getString(item, ['status'], 'not recorded')} tone={getString(item, ['status'], '') ? artifactReviewBadgeTone(getString(item, ['status'], '')) : 'muted'} fallback="not recorded" />
                          {getString(item, ['reference_id', 'approval_id'], '') ? <> · <code className="mono-hash">{getString(item, ['reference_id', 'approval_id'], '')}</code></> : null}
                        </strong>
                      </div>
                    ))}
                  </div>
                )}
              </CardContent>
            </Card></div>
          ) : null}
        </>
      ) : null}
    </div>
  );
}


function SocRequestDetailView({
  entity,
  entityId,
  config,
  session,
  onRefresh,
  tenantId: tenantIdProp
}: {
  entity: DataItem;
  entityId: string;
  config: PortalConfig;
  session: Session;
  onRefresh: () => Promise<void>;
  /** Cross-tenant staff SOC scope (from Open link query or entity.tenant_id). */
  tenantId?: string;
}) {
  const { confirm } = useConfirmModal();
  const [tab, setTab] = useState('workspace');
  const [busy, setBusy] = useState('');
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');
  const [adapterStatus, setAdapterStatus] = useState<DataItem | null>(null);
  const [socNotes, setSocNotes] = useState<DataItem[]>([]);
  const [notesLoading, setNotesLoading] = useState(false);
  const [notesError, setNotesError] = useState('');
  const [postTestReport, setPostTestReport] = useState<DataItem | null>(null);
  const [reportBusy, setReportBusy] = useState(false);
  const [postTestReportError, setPostTestReportError] = useState('');
  const staffSocSurface = session.principal === 'staff' && isStaffSocRole(session);
  const isSoc = staffSocSurface || (session.role === 'soc' && session.principal !== 'staff');
  const actionTenantId =
    String(tenantIdProp ?? '').trim()
    || getString(entity, ['tenant_id'], '')
    || session.tenant_id
    || undefined;

  async function socFetch(path: string, options: { method?: string; body?: unknown; tenantId?: string } = {}) {
    if (staffSocSurface) {
      return requestSocJson(config, session, path, {
        method: options.method,
        body: options.body,
        tenantId: options.tenantId ?? actionTenantId
      });
    }
    return requestJson(config, session, path, options);
  }

  async function loadPostTestReport() {
    setReportBusy(true);
    setPostTestReportError('');
    try {
      const payload = await socFetch(`/internal/soc/high-scale/${encodeURIComponent(entityId)}/post-test-report`);
      const record = payload as DataItem | null;
      if (record && typeof record === 'object' && !record.error && getString(record, ['id'], '')) {
        setPostTestReport(record);
      } else {
        setPostTestReport(null);
      }
    } catch (err) {
      setPostTestReport(null);
      setPostTestReportError(err instanceof Error ? err.message : 'Post-test report status could not be loaded.');
    } finally {
      setReportBusy(false);
    }
  }

  async function submitPostTestReport(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const customer_summary = String(form.get('customer_summary') ?? '').trim();
    const impact_summary = String(form.get('impact_summary') ?? '').trim();
    if (!customer_summary && !impact_summary) {
      setError('Add a customer summary or impact summary before attaching the post-test report.');
      return;
    }
    setBusy(`report-${entityId}`);
    setError('');
    setMessage('');
    try {
      await socFetch(`/internal/soc/high-scale/${encodeURIComponent(entityId)}/post-test-report`, {
        method: 'POST',
        body: { customer_summary, impact_summary }
      });
      setMessage('Post-test report attached. You can now close the request.');
      await loadPostTestReport();
      await onRefresh();
    } catch (err) {
      setError(apiErrorMessage(err, 'Attach post-test report failed.'));
    } finally {
      setBusy('');
    }
  }
  const artifacts = Array.isArray(entity.artifacts) ? entity.artifacts as DataItem[] : [];
  const packStatus = getNestedItem(entity, ['authorization_pack_status']);
  const title = detailEntityTitle('queue-detail', entity, entityId);
  const providerChecklist = Array.isArray(entity.provider_approval_checklist) ? entity.provider_approval_checklist as DataItem[] : [];
  const lifecycleTrail = buildLifecycleTimeline(entity);
  const tabOptions = [
    { id: 'workspace', label: 'Workspace' },
    { id: 'artifacts', label: 'Artifacts' },
    { id: 'provider', label: 'Provider' },
    { id: 'adapter', label: 'Adapter' },
    { id: 'notes', label: 'Notes' }
  ];

  async function socAction(action: string, body: Record<string, unknown> = {}) {
    const lifecycleConfirm: Record<string, string> = {
      approve: `Approve high-scale request ${entityId} and move it to approved?`,
      schedule: `Schedule high-scale request ${entityId} for execution?`,
      start: `Start high-scale execution for ${entityId}? Governed adapter traffic will begin.`,
      stop: `Stop high-scale execution for ${entityId} immediately?`,
      close: `Close high-scale request ${entityId} and finalize the test lifecycle?`
    };
    const lifecycleMessage = lifecycleConfirm[action];
    if (lifecycleMessage && !(await confirm({
      title: `${formatStatusLabel(action)} high-scale request`,
      description: lifecycleMessage,
      confirmLabel: formatStatusLabel(action),
      confirmTone: action === 'approve' || action === 'schedule' || action === 'start' ? 'default' : 'danger'
    }))) return;
    setBusy(`${action}-${entityId}`);
    setError('');
    setMessage('');
    try {
      await socFetch(`/internal/soc/high-scale/${encodeURIComponent(entityId)}/${action}`, { method: 'POST', body });
      setMessage(`SOC ${action} completed.`);
      await onRefresh();
    } catch (err) {
      setError(apiErrorMessage(err, 'SOC action failed.'));
    } finally {
      setBusy('');
    }
  }

  async function reviewArtifact(artifactId: string, status: 'accepted' | 'rejected') {
    if (status === 'accepted') {
      if (!await confirm({ title: 'Accept authorization artifact', description: 'Accept this authorization artifact? Acceptance authorizes high-scale execution to proceed.', confirmLabel: 'Accept artifact', confirmTone: 'default' })) return;
    } else if (!await confirm({ title: 'Reject authorization artifact', description: 'Reject this authorization artifact?', confirmLabel: 'Reject artifact' })) return;
    await socAction(`artifacts/${artifactId}/review`, { status, notes: `SOC ${status} via request detail` });
  }

  async function loadAdapterStatus() {
    setBusy(`adapter-${entityId}`);
    setError('');
    try {
      const payload = await socFetch(`/internal/soc/high-scale/${encodeURIComponent(entityId)}/adapter-status`);
      setAdapterStatus(payload as DataItem);
    } catch (err) {
      setError(apiErrorMessage(err, 'Adapter status unavailable.'));
      setAdapterStatus(null);
    } finally {
      setBusy('');
    }
  }

  async function submitSocNote(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = event.currentTarget;
    const body = String(new FormData(form).get('body') ?? '').trim();
    if (!body) return;
    await socAction('notes', { body });
    form.reset();
    void loadSocNotes();
  }

  async function loadSocNotes() {
    setNotesLoading(true);
    setNotesError('');
    try {
      const payload = await socFetch(`/internal/soc/high-scale/${encodeURIComponent(entityId)}/notes`);
      if (!payload || typeof payload !== 'object' || Array.isArray(payload) || !Array.isArray((payload as { items?: unknown }).items)) {
        throw new Error('Invalid SOC notes response.');
      }
      const items = (payload as { items: unknown[] }).items;
      if (!items.every((item) => item && typeof item === 'object' && !Array.isArray(item))) {
        throw new Error('Invalid SOC note records.');
      }
      setSocNotes(items as DataItem[]);
    } catch (err) {
      setSocNotes([]);
      setNotesError(err instanceof Error ? err.message : 'SOC notes could not be loaded.');
    } finally {
      setNotesLoading(false);
    }
  }

  useEffect(() => {
    if (!isSoc || !entityId) return;
    void loadSocNotes();
  }, [entityId, isSoc]);

  useEffect(() => {
    if (!isSoc || !entityId || getString(entity, ['state'], '') !== 'stopped') {
      setPostTestReport(null);
      setPostTestReportError('');
      return;
    }
    void loadPostTestReport();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [entityId, isSoc, entity]);

  if (!isSoc) {
    const isStaffPrincipal = session.principal === 'staff';
    return (
      <div className="content">
        <DetailPageIntro route="queue-detail" eyebrow="SOC execution workspace" />
        <EmptyState
          icon={ShieldCheck}
          title={isStaffPrincipal ? 'Staff SOC role required.' : 'SOC role required.'}
          body={isStaffPrincipal
            ? 'Sign in with a staff SOC analyst or lead role to operate governed high-scale requests.'
            : 'Switch the workspace role to soc to operate governed high-scale requests.'}
          actionLabel={isStaffPrincipal ? 'Open staff login' : 'Open SOC console'}
          actionHref={isStaffPrincipal ? '/internal/admin/login' : '#internal-soc'}
        />
      </div>
    );
  }

  const state = getString(entity, ['state'], '');
  const packReady = getNestedString(entity, ['authorization_pack_status', 'overall'], '') === 'accepted';
  const hasPostTestReport = Boolean(postTestReport && getString(postTestReport, ['id'], ''));
  // Pre-flight gates + KPI strip are derived from real request evidence only.
  const requestedWindowStart = getNestedString(entity, ['requested_window', 'window_start'], '');
  const requestedWindowEnd = getNestedString(entity, ['requested_window', 'window_end'], '');
  const windowStart = getNestedString(entity, ['scheduled_window', 'window_start'], '');
  const windowEnd = getNestedString(entity, ['scheduled_window', 'window_end'], '');
  const windowConfirmed = Boolean(windowStart && windowEnd);
  const scopeRecorded = Boolean(getString(entity, ['scope_hash'], '') || getNestedItem(entity, ['scope_confirmation']));
  const socApprovalsCount = Array.isArray(entity.soc_approvals) ? (entity.soc_approvals as DataItem[]).length : 0;
  const stateTone = highScaleStateBadgeTone(state);
  const preflightGates = [
    { label: 'Authorization pack accepted', pass: packReady },
    { label: 'Safe window confirmed', pass: windowConfirmed },
    { label: 'Scope hash recorded', pass: scopeRecorded },
    { label: 'SOC approval recorded', pass: socApprovalsCount > 0 }
  ];
  const preflightReady = preflightGates.every((gate) => gate.pass);

  return (
    <div className="content">
      <DetailPageHeader route="queue-detail" eyebrow="SOC execution workspace" entityId={entityId} title={title} />
      <PageContextSummary>
        <StatusBadge value={state} tone={highScaleStateBadgeTone(state)} fallback="submitted" /> · tenant <code>{actionTenantId ?? 'not recorded'}</code>
      </PageContextSummary>
      <DetailStatusBanners error={error} message={message} hideMessageWhenLoadError={false} />
      <div className="metric-grid four">
        <MetricCard label="State" value={formatStatusLabel(state, 'submitted')} sub="Governed lifecycle state" icon={ShieldCheck} tone={stateTone === 'danger' ? 'danger' : stateTone === 'warn' ? 'warn' : stateTone === 'success' ? 'success' : 'info'} />
        <MetricCard label="Pack" value={formatStatusLabel(getString(packStatus ?? {}, ['overall'], 'missing'), 'missing')} sub="Authorization pack review" icon={FileCheck2} tone={packReady ? 'success' : 'warn'} />
        <MetricCard label="Target group" value={getString(entity, ['target_group_name', 'target_group_label'], 'Declared target group')} sub="Declared scope under request" icon={Target} tone="muted" />
        <MetricCard label="Window" value={windowConfirmed ? formatDate(windowStart) : 'Unscheduled'} sub={windowConfirmed ? 'Confirmed safe window' : 'Awaiting schedule'} icon={Activity} tone={windowConfirmed ? 'info' : 'muted'} />
      </div>
      <Card>
        <CardHeader>
          <CardTitle>Go / No-Go gates</CardTitle>
          <CardDescription>Pre-flight readiness derived from real request evidence. Every gate must pass before governed execution starts.</CardDescription>
        </CardHeader>
        <CardContent>
          <ul className="placement-gates" aria-label="Pre-flight execution gates">
            {preflightGates.map((gate) => (
              <li key={gate.label}>
                <ShieldCheck size={14} aria-hidden="true" />
                <span>{gate.label}</span>
                <Badge tone={gate.pass ? 'success' : 'muted'} aria-label={`${gate.label}: ${gate.pass ? 'pass' : 'pending'}`}>{gate.pass ? 'pass' : 'pending'}</Badge>
              </li>
            ))}
          </ul>
        </CardContent>
      </Card>
      <Tabs value={tab} options={tabOptions} onChange={setTab} className="tabs-wrap" ariaLabel="SOC queue detail sections"
            getTabId={(id) => `soc-queue-detail-sections-tab-${id}`}
            getPanelId={(id) => `soc-queue-detail-sections-panel-${id}`} />
      {tab === 'workspace' ? (
        <div role="tabpanel" id="soc-queue-detail-sections-panel-workspace" aria-labelledby="soc-queue-detail-sections-tab-workspace" className="tab-panel"><>
        <Card>
          <CardHeader><CardTitle>Queue context</CardTitle><CardDescription>Lifecycle actions for this request</CardDescription></CardHeader>
          <CardContent className="kv-list">
            <div><span>State</span><StatusBadge value={state} tone={highScaleStateBadgeTone(state)} /></div>
            <div><span>Pack</span><StatusBadge value={getString(packStatus ?? {}, ['overall'], 'missing')} tone={artifactReviewBadgeTone(getString(packStatus ?? {}, ['overall'], 'missing'))} fallback="missing" /></div>
            <div className="row-actions">
              {['submitted', 'under_review'].includes(state) && packReady ? <Button size="sm" variant="secondary" loading={busy === `approve-${entityId}`} disabled={busy !== ''} onClick={() => void socAction('approve')}>Approve</Button> : null}
              {state === 'approved' ? <Button size="sm" variant="secondary" loading={busy === `schedule-${entityId}`} disabled={busy !== ''} onClick={() => void socAction('schedule', socDevScheduleWindow())}>Schedule</Button> : null}
              {state === 'scheduled' ? <Button size="sm" variant="default" loading={busy === `start-${entityId}`} disabled={busy !== '' || !preflightReady} title={preflightReady ? undefined : 'All displayed Go / No-Go gates must pass before start'} onClick={() => void socAction('start')}>Start</Button> : null}
              {state === 'running' ? <Button size="sm" variant="danger" loading={busy === `stop-${entityId}`} disabled={busy !== ''} onClick={() => void socAction('stop')}>Stop</Button> : null}
              {state === 'stopped' && hasPostTestReport ? <Button size="sm" variant="secondary" loading={busy === `close-${entityId}`} disabled={busy !== ''} onClick={() => void socAction('close')}>Close</Button> : null}
              {state === 'stopped' && !hasPostTestReport ? <Button size="sm" variant="secondary" disabled title={postTestReportError || 'Attach a post-test report before closing'}>Close</Button> : null}
              <AnchorButton size="sm" variant="ghost" href="#internal-soc">Open SOC console</AnchorButton>
            </div>
            {state === 'stopped' && reportBusy ? <p className="muted small">Checking for an attached post-test report…</p> : null}
            {state === 'stopped' && !reportBusy && postTestReportError ? <div className="form-banner error" role="alert">{postTestReportError} Closing remains disabled until report status can be confirmed.</div> : null}
            {state === 'stopped' && !reportBusy && hasPostTestReport ? (
              <p className="muted small">Post-test report attached — this request can be closed. Closing finalizes the governed test lifecycle.</p>
            ) : null}
            {state === 'stopped' && !reportBusy && !postTestReportError && !hasPostTestReport ? (
              <div className="stack-tight">
                <p className="muted small">Attach a post-test report before closing. The governed lifecycle rejects Close until the report is attached.</p>
                <form className="product-form" aria-busy={busy === `report-${entityId}` || undefined} onSubmit={(event) => void submitPostTestReport(event)}>
                  <label className="full"><span>Customer summary</span><textarea name="customer_summary" rows={2} disabled={busy === `report-${entityId}`} placeholder="Customer-facing summary of the governed high-scale test outcome." /></label>
                  <label className="full"><span>Impact summary</span><textarea name="impact_summary" rows={2} disabled={busy === `report-${entityId}`} placeholder="Impact, residual risk, and recommended next steps." /></label>
                  <div className="form-actions full"><Button type="submit" size="sm" variant="default" loading={busy === `report-${entityId}`} disabled={busy !== ''}>Attach post-test report</Button></div>
                </form>
              </div>
            ) : null}
          </CardContent>
        </Card>
        <div className="dash-grid">
          <Card>
            <CardHeader><CardTitle>Request facts</CardTitle><CardDescription>Tenant, scope, purpose, and safe-window fields returned with this queue item.</CardDescription></CardHeader>
            <CardContent className="kv-list">
              <div><span>Request</span><strong title={entityId}>{title}</strong></div>
              <div><span>Tenant</span><strong>{actionTenantId ?? 'not recorded'}</strong></div>
              <div><span>Target group</span>{getString(entity, ['target_group_id'], '') ? <DetailEntityLink route="target-group-detail" id={getString(entity, ['target_group_id'], '')} /> : <strong>not recorded</strong>}</div>
              <div><span>Reason</span><strong>{getString(entity, ['reason'], 'not recorded')}</strong></div>
              <div><span>Objective</span><strong>{getString(entity, ['objective'], 'not recorded')}</strong></div>
              <div><span>Requested by</span><strong>{getString(entity, ['created_by', 'requested_by'], 'not recorded')}</strong></div>
              <div><span>Requested window</span><strong>{requestedWindowStart && requestedWindowEnd ? `${formatDate(requestedWindowStart)} → ${formatDate(requestedWindowEnd)}` : 'not fully recorded'}</strong></div>
              <div><span>Scheduled window</span><strong>{windowConfirmed ? `${formatDate(windowStart)} → ${formatDate(windowEnd)}` : 'not scheduled'}</strong></div>
              {getString(entity, ['scope_hash'], '') ? <div><span>Scope hash</span><strong title={getString(entity, ['scope_hash'], '')}>Recorded</strong></div> : null}
            </CardContent>
          </Card>
          <Card>
            <CardHeader><CardTitle>Lifecycle</CardTitle><CardDescription>Ordered request transitions recorded by the high-scale workflow.</CardDescription></CardHeader>
            <CardContent><TimelinePanel items={lifecycleTrail.map((event) => ({ label: event.action, at: event.at }))} /></CardContent>
          </Card>
        </div>
        </></div>
      ) : null}
      {tab === 'artifacts' ? (
        <div role="tabpanel" id="soc-queue-detail-sections-panel-artifacts" aria-labelledby="soc-queue-detail-sections-tab-artifacts" className="tab-panel"><Card>
          <CardHeader><CardTitle>Authorization artifacts</CardTitle></CardHeader>
          <CardContent>
            {artifacts.length === 0 ? <p className="muted">No artifacts uploaded.</p> : (
              <div className="kv-list">
                {artifacts.map((artifact) => {
                  const artifactId = getString(artifact, ['id'], '');
                  const type = getString(artifact, ['type']);
                  const reviewBusy = busy === `artifacts/${artifactId}/review-${entityId}`;
                  return (
                    <div key={artifactId || type}>
                      <span>{authorizationArtifactTitle(type)}</span>
                      <div className="row-actions">
                        <StatusBadge value={getString(artifact, ['status'])} tone={artifactReviewBadgeTone(getString(artifact, ['status']))} />
                        <Button size="sm" variant="secondary" loading={reviewBusy} disabled={busy !== ''} onClick={() => void reviewArtifact(artifactId, 'accepted')}>Accept</Button>
                        <Button size="sm" variant="ghost" loading={reviewBusy} disabled={busy !== ''} onClick={() => void reviewArtifact(artifactId, 'rejected')}>Reject</Button>
                      </div>
                      {getString(artifact, ['content_sha256'], '') ? <p className="muted small mono mono-hash">SHA-256 {getString(artifact, ['content_sha256'], '')}</p> : null}
                      <p className="muted small">{explainArtifactReviewStatus(type, packRequirementForType(packStatus, type), artifact)}</p>
                    </div>
                  );
                })}
              </div>
            )}
          </CardContent>
        </Card></div>
      ) : null}
      {tab === 'provider' ? (
        <div role="tabpanel" id="soc-queue-detail-sections-panel-provider" aria-labelledby="soc-queue-detail-sections-tab-provider" className="tab-panel"><Card>
          <CardHeader><CardTitle>Provider checklist</CardTitle><CardDescription>Recorded provider approvals and requirements. Request state alone does not prove provider readiness.</CardDescription></CardHeader>
          <CardContent>
            {providerChecklist.length === 0 ? (
              <EmptyState icon={ClipboardList} title="No provider checklist returned." body="No provider approval records are available for this request." />
            ) : (
              <div className="kv-list">
                {providerChecklist.map((item, index) => (
                  <div key={getString(item, ['id'], String(index))}>
                    <span>{getString(item, ['provider_name', 'label', 'requirement'], 'Provider requirement')}</span>
                    <strong>
                      <StatusBadge value={getString(item, ['status'], 'not recorded')} tone={getString(item, ['status'], '') ? artifactReviewBadgeTone(getString(item, ['status'], '')) : 'muted'} fallback="not recorded" />
                      {getString(item, ['reference_id', 'approval_id'], '') ? <> · <code className="mono-hash">{getString(item, ['reference_id', 'approval_id'], '')}</code></> : null}
                    </strong>
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card></div>
      ) : null}
      {tab === 'adapter' ? (
        <div role="tabpanel" id="soc-queue-detail-sections-panel-adapter" aria-labelledby="soc-queue-detail-sections-tab-adapter" className="tab-panel"><Card>
          <CardHeader><CardTitle>Adapter status</CardTitle></CardHeader>
          <CardContent>
            <Button size="sm" variant="secondary" loading={busy === `adapter-${entityId}`} disabled={busy !== ''} onClick={() => void loadAdapterStatus()}>Refresh adapter status</Button>
            {adapterStatus ? (
              <div className="kv-list">
                <div><span>State</span><strong>{getNestedString(adapterStatus, ['adapter', 'state'], getString(adapterStatus, ['state'], 'not returned'))}</strong></div>
                <div><span>Traffic generated</span>{getNestedString(adapterStatus, ['adapter', 'traffic_generated'], '') ? <Badge tone={getNestedString(adapterStatus, ['adapter', 'traffic_generated'], '') === 'true' ? 'warn' : 'muted'}>{getNestedString(adapterStatus, ['adapter', 'traffic_generated'], '') === 'true' ? 'Yes' : 'No'}</Badge> : <strong>not returned</strong>}</div>
                <div><span>Provider reference</span><strong>{getNestedString(adapterStatus, ['adapter', 'provider_reference'], getString(adapterStatus, ['provider_reference'], 'not returned'))}</strong></div>
              </div>
            ) : <p className="muted">Adapter status has not been requested. No provider telemetry is inferred.</p>}
          </CardContent>
        </Card></div>
      ) : null}
      {tab === 'notes' ? (
        <div role="tabpanel" id="soc-queue-detail-sections-panel-notes" aria-labelledby="soc-queue-detail-sections-tab-notes" className="tab-panel"><Card>
          <CardHeader><CardTitle>SOC notes</CardTitle><CardDescription>Thread before adding execution context.</CardDescription></CardHeader>
          <CardContent>
            {notesLoading ? <DetailLoadingPlaceholder label="Loading SOC notes…" variant="compact" /> : null}
            {notesError ? <div className="form-banner error" role="alert">{notesError} No empty note history is being assumed.</div> : null}
            {socNotes.length > 0 ? (
              <div className="kv-list stack-tight">
                {socNotes.map((note, index) => (
                  <div key={getString(note, ['id'], String(index))}>
                    <span>{formatDate(note.created_at)}</span>
                    <strong>{getString(note, ['body'])}</strong>
                  </div>
                ))}
              </div>
            ) : !notesLoading && !notesError ? <p className="muted">The notes endpoint returned a valid empty items array.</p> : null}
            <form className="product-form" aria-busy={notesLoading || undefined} onSubmit={(event) => void submitSocNote(event)}>
              <label className="full"><span>Note</span><textarea name="body" rows={4} disabled={notesLoading} placeholder="Execution context, customer coordination, or stop rationale." /></label>
              <div className="form-actions full"><Button type="submit" loading={busy === `notes-${entityId}`} disabled={busy !== '' || notesLoading}>Add note</Button></div>
            </form>
          </CardContent>
        </Card></div>
      ) : null}
    </div>
  );
}

/**
 * Whole-row click-through props matching the prototype's `role="link"` rows.
 * Navigates to a detail route via the hash + `?id=` pattern (see lib/route-params).
 */
function detailRowNavProps(route: RouteId, id: string): Omit<HTMLAttributes<HTMLTableRowElement>, 'key'> {
  if (!id) return {};
  const go = () => { window.location.hash = `${route}?id=${encodeURIComponent(id)}`; };
  return {
    role: 'link',
    tabIndex: 0,
    style: { cursor: 'pointer' },
    'aria-label': `Open ${id}`,
    onClick: go,
    onKeyDown: (event: KeyboardEvent<HTMLTableRowElement>) => {
      if (event.key === 'Enter' || event.key === ' ') {
        event.preventDefault();
        go();
      }
    }
  };
}

/** Verdict/outcome badge tone shared by the check/policy detail surfaces. */
function outcomeBadgeTone(value: string): StatusBadgeTone {
  const key = normalizeStatusKey(value);
  if (['pass', 'passed', 'success', 'ok', 'covered'].includes(key)) return 'success';
  if (['fail', 'failed', 'gap', 'edge_exposed', 'bypassable', 'penetrated', 'exposed', 'unprotected'].includes(key)) return 'danger';
  if (['review', 'manual_review', 'warn', 'warning', 'partial', 'inconclusive', 'needs_evidence'].includes(key)) return 'warn';
  if (['soc_gated', 'request', 'pending', 'none'].includes(key)) return 'muted';
  return 'info';
}

const CHECK_VECTOR_FAMILY_LABELS: Record<string, string> = {
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

function formatCheckFamilyLabel(family: string) {
  if (!family) return '—';
  return CHECK_VECTOR_FAMILY_LABELS[family] ?? formatFactorLabel(family);
}

function formatCheckModeLabel(safetyClass: string) {
  if (safetyClass === 'safe') return 'safe';
  if (safetyClass === 'soc_gated') return 'SOC-gated';
  return safetyClass ? formatFactorLabel(safetyClass) : '—';
}

type CheckExecutionSemantics = {
  kind: string;
  cap: string;
  profileKind: string;
};

function checkProbeOperationBoundLabel(maxRequests: number) {
  const probeOperations = maxRequests === 1 ? '1 probe operation' : `Up to ${maxRequests} probe operations`;
  return `${probeOperations} + up to two DNS destination-vetting resolver operations per hostname destination`;
}

/** Catalog-backed execution meaning; a one-operation network probe is never called metadata. */
function checkExecutionSemantics(check: DataItem): CheckExecutionSemantics {
  const safetyClass = getString(check, ['safety_class'], '');
  const profileKind = getNestedString(check, ['probe_profile', 'kind'], '');
  const maxRequests = getNestedNumber(check, ['probe_profile', 'max_requests'], NaN);
  if (safetyClass === 'soc_gated') return { kind: 'Request only', cap: 'No customer execution', profileKind };
  if (profileKind === 'metadata_marker') return { kind: 'Metadata evaluation', cap: 'No network I/O', profileKind };
  if (profileKind === 'ops_readiness') return { kind: 'Operations self-check', cap: '1 self-check', profileKind };
  if (Number.isFinite(maxRequests) && maxRequests > 0) {
    return { kind: 'Bounded live probe', cap: checkProbeOperationBoundLabel(maxRequests), profileKind };
  }

  const maxRate = check.max_rate;
  if (typeof maxRate === 'number' && Number.isFinite(maxRate) && maxRate > 0) {
    return { kind: 'Bounded live probe', cap: `Up to ${maxRate} RPS`, profileKind };
  }
  if (typeof maxRate === 'string' && maxRate.trim()) {
    return { kind: 'Bounded live probe', cap: maxRate.replace(/_/g, ' '), profileKind };
  }
  if (profileKind) return { kind: 'Bounded live probe', cap: getString(check, ['bound', 'rate_limit'], 'Catalog cap not recorded'), profileKind };
  return { kind: 'Execution metadata unavailable', cap: 'Catalog cap not recorded', profileKind };
}

function catalogValueList(value: unknown): string[] {
  const entries = Array.isArray(value) ? value : value == null || value === '' ? [] : [value];
  const values = entries.flatMap((entry) => {
    if (typeof entry === 'string' || typeof entry === 'number') return [String(entry).trim()];
    if (!entry || typeof entry !== 'object' || Array.isArray(entry)) return [];
    const item = entry as DataItem;
    const key = ['id', 'value', 'key', 'attack_vector_id', 'exhausted_resource', 'delivery_pattern', 'waf_vulnerability_id', 'non_ddos_threat_id']
      .find((candidate) => item[candidate] !== undefined && item[candidate] !== null && item[candidate] !== '');
    return key ? [String(item[key]).trim()] : [];
  }).filter(Boolean);
  return [...new Set(values)];
}

const GENERIC_CHECK_REMEDIATION = 'Review edge protection for this vector.';
const GENERIC_CHECK_EXPLANATION = 'The verdict follows the bounded external probe result.';
const GENERIC_CHECK_VERDICT_LOGIC = 'Verdict when probe external_result aligns with the check default_expected_behavior.';

function executionSpecificCheckCopy(kind: 'remediation' | 'explanation' | 'verdict', execution: CheckExecutionSemantics) {
  if (execution.kind === 'Request only') {
    if (kind === 'remediation') return 'Review authorization, declared scope, and SOC prerequisites before requesting this scenario.';
    if (kind === 'explanation') return 'This catalog entry describes a governed request-only scenario. It performs no customer-side execution.';
    return 'A verdict requires evidence recorded by the governed SOC workflow; this catalog entry does not execute for customers.';
  }
  if (execution.kind === 'Metadata evaluation') {
    if (kind === 'remediation') return 'Review the catalog inputs and recorded metadata that produced this result.';
    if (kind === 'explanation') return 'This check evaluates recorded metadata and performs no network I/O.';
    return 'The verdict follows the recorded metadata inputs and the catalog expected-behavior key.';
  }
  if (execution.kind === 'Operations self-check') {
    if (kind === 'remediation') return 'Review the failed readiness prerequisite and update the corresponding operating control.';
    if (kind === 'explanation') return 'This is an operations-readiness self-check, not a live outside-probe assertion.';
    return 'The verdict follows the recorded self-check result and the catalog expected-behavior key.';
  }
  if (kind === 'remediation') return 'Review the recorded run evidence and declared target behavior before changing protection.';
  if (kind === 'explanation') return 'The verdict uses the evidence types declared for this bounded external probe.';
  return 'Compare the bounded probe evidence recorded for this check with its catalog expected-behavior key.';
}

function runVerdictValue(run: DataItem) {
  const verdict = run.verdict;
  if (verdict && typeof verdict === 'object' && !Array.isArray(verdict)) {
    const nested = getString(verdict as DataItem, ['verdict', 'status', 'result'], '');
    if (nested) return nested;
  }
  return getString(run, ['verdict'], '');
}

/** Latest completed/verdicted run outcome for a given check id. */
function latestCheckVerdict(runs: DataItem[], evidence: DataItem[], checkId: string): { verdict: string; runId: string } | null {
  let best: { verdict: string; runId: string; at: string } | null = null;
  for (const run of runs) {
    if (getString(run, ['check_id'], '') !== checkId) continue;
    if (!['completed', 'verdicted'].includes(getString(run, ['status'], ''))) continue;
    if (!hasEvidenceBackedVerdict(run, evidence)) continue;
    const verdict = runVerdictValue(run);
    if (!verdict) continue;
    const at = String(run.updated_at ?? run.completed_at ?? run.started_at ?? run.created_at ?? '');
    if (!best || at.localeCompare(best.at) >= 0) {
      best = { verdict, runId: getString(run, ['id'], ''), at };
    }
  }
  return best ? { verdict: best.verdict, runId: best.runId } : null;
}

/** Latest run outcome for a given target group id. */
function latestGroupVerdict(runs: DataItem[], evidence: DataItem[], groupId: string): { verdict: string; runId: string } | null {
  let best: { verdict: string; runId: string; at: string } | null = null;
  for (const run of runs) {
    if (getString(run, ['target_group_id'], '') !== groupId) continue;
    if (!hasEvidenceBackedVerdict(run, evidence)) continue;
    const verdict = runVerdictValue(run);
    if (!verdict) continue;
    const at = String(run.updated_at ?? run.completed_at ?? run.started_at ?? run.created_at ?? '');
    if (!best || at.localeCompare(best.at) >= 0) {
      best = { verdict, runId: getString(run, ['id'], ''), at };
    }
  }
  return best ? { verdict: best.verdict, runId: best.runId } : null;
}

function formatPolicySafeWindow(policy: DataItem) {
  const windows = policy.safe_windows;
  if (Array.isArray(windows) && windows.length > 0 && windows[0] && typeof windows[0] === 'object') {
    const first = windows[0] as DataItem;
    const day = getString(first, ['day'], '');
    const start = getString(first, ['start'], '');
    const end = getString(first, ['end'], '');
    if (start || end) {
      const range = start && end ? `${start}–${end}` : start || end;
      return day ? `${day} ${range}` : range;
    }
  }
  return getString(policy, ['safe_window', 'window'], '—');
}

/** Declared targets for labels and caller context; routes that do not preload them fetch once. */
function useDeclaredTargets(data: PortalData, config: PortalConfig, session: Session) {
  const preloaded = data.targets.length > 0;
  const [state, setState] = useState<{ status: 'idle' | 'loading' | 'loaded' | 'error'; items: DataItem[] }>({ status: 'idle', items: [] });
  useEffect(() => {
    if (preloaded) return undefined;
    let cancelled = false;
    setState({ status: 'loading', items: [] });
    requestJson(config, session, '/v1/targets')
      .then((payload) => {
        if (cancelled) return;
        const items = payload && typeof payload === 'object' && Array.isArray((payload as { items?: unknown }).items)
          ? (payload as { items: DataItem[] }).items
          : [];
        setState({ status: 'loaded', items });
      })
      .catch(() => { if (!cancelled) setState({ status: 'error', items: [] }); });
    return () => { cancelled = true; };
  }, [config, session, preloaded]);
  return preloaded ? data.targets : state.items;
}

function CheckDetailPage({
  entityId,
  data,
  config,
  session
}: {
  entityId: string;
  data: PortalData;
  config: PortalConfig;
  session: Session;
}) {
  const callerPolicyId = getRouteParam('policy');
  const callerTargetId = getRouteParam('target');
  const [linkedPolicyState, setLinkedPolicyState] = useState<{
    status: 'idle' | 'loading' | 'loaded' | 'error';
    items: DataItem[];
    error: string;
  }>({ status: 'idle', items: [], error: '' });
  const [policyReload, setPolicyReload] = useState(0);
  const [runReload, setRunReload] = useState(0);

  useEffect(() => {
    if (!entityId) {
      setLinkedPolicyState({ status: 'idle', items: [], error: '' });
      return;
    }
    let cancelled = false;
    setLinkedPolicyState({ status: 'loading', items: [], error: '' });
    requestJson(config, session, '/v1/test-policies')
      .then((payload) => {
        if (cancelled) return;
        if (!payload || typeof payload !== 'object' || Array.isArray(payload) || !Array.isArray((payload as { items?: unknown }).items)) {
          throw new Error('Invalid schedule list response.');
        }
        const items = (payload as { items: unknown[] }).items;
        if (!items.every((item) => item && typeof item === 'object' && !Array.isArray(item))) {
          throw new Error('Invalid schedule records.');
        }
        setLinkedPolicyState({
          status: 'loaded',
          items: (items as DataItem[]).filter((item) => getString(item, ['check_id'], '') === entityId),
          error: ''
        });
      })
      .catch((err) => {
        if (!cancelled) {
          setLinkedPolicyState({ status: 'error', items: [], error: err instanceof Error ? err.message : 'Could not load linked schedules.' });
        }
      });
    return () => { cancelled = true; };
  }, [config, session, entityId, policyReload]);

  // The shared runs dataset is only the newest page; fetch this check's own runs (and the caller target's).
  const [checkRunState, setCheckRunState] = useState<{ status: 'idle' | 'loading' | 'loaded' | 'error'; items: DataItem[]; error: string }>({ status: 'idle', items: [], error: '' });
  useEffect(() => {
    if (!entityId) {
      setCheckRunState({ status: 'idle', items: [], error: '' });
      return;
    }
    let cancelled = false;
    setCheckRunState({ status: 'loading', items: [], error: '' });
    const targetQuery = callerTargetId ? `&target_id=${encodeURIComponent(callerTargetId)}` : '';
    requestJson(config, session, `/v1/test-runs?check_id=${encodeURIComponent(entityId)}${targetQuery}&limit=25`)
      .then((payload) => {
        if (cancelled) return;
        const items = payload && typeof payload === 'object' && !Array.isArray(payload)
          ? (payload as { items?: unknown }).items
          : null;
        if (!Array.isArray(items) || !items.every((item) => item && typeof item === 'object' && !Array.isArray(item))) {
          throw new Error('Invalid test-run list response.');
        }
        setCheckRunState({ status: 'loaded', items: (items as DataItem[]).filter((run) => getString(run, ['check_id'], '') === entityId), error: '' });
      })
      .catch((err) => {
        if (!cancelled) setCheckRunState({ status: 'error', items: [], error: err instanceof Error ? err.message : 'Recorded results could not be loaded.' });
      });
    return () => { cancelled = true; };
  }, [config, session, entityId, callerTargetId, runReload]);

  const declaredTargets = useDeclaredTargets(data, config, session);
  const [exactCheck, setExactCheck] = useState<{ id: string; status: 'loading' | 'found' | 'not_found' | 'error'; check: DataItem | null; error: string }>({ id: '', status: 'loading', check: null, error: '' });
  const [exactCheckTick, setExactCheckTick] = useState(0);
  const [compatibility, setCompatibility] = useState<{ status: 'idle' | 'loading' | 'loaded' | 'not_found' | 'error'; checks: DataItem[] }>({ status: 'idle', checks: [] });

  useEffect(() => {
    if (!entityId) return undefined;
    let cancelled = false;
    setExactCheck({ id: entityId, status: 'loading', check: null, error: '' });
    requestJson(config, session, `/v1/checks/${encodeURIComponent(entityId)}`)
      .then((payload) => {
        if (cancelled) return;
        const found = getNestedItem(payload as DataItem, ['check']);
        setExactCheck(found ? { id: entityId, status: 'found', check: found, error: '' } : { id: entityId, status: 'not_found', check: null, error: '' });
      })
      .catch((err) => {
        if (cancelled) return;
        const status = Number((err as { status?: unknown })?.status ?? 0);
        setExactCheck({ id: entityId, status: status === 404 ? 'not_found' : 'error', check: null, error: err instanceof Error ? err.message : 'Check could not be loaded.' });
      });
    return () => { cancelled = true; };
  }, [config, session, entityId, exactCheckTick]);

  useEffect(() => {
    if (!callerTargetId) {
      setCompatibility({ status: 'idle', checks: [] });
      return undefined;
    }
    let cancelled = false;
    setCompatibility({ status: 'loading', checks: [] });
    requestJson(config, session, `/v1/targets/${encodeURIComponent(callerTargetId)}/compatible-checks`)
      .then((payload) => {
        if (cancelled) return;
        const checks = Array.isArray((payload as DataItem)?.checks) ? (payload as DataItem).checks as DataItem[] : [];
        setCompatibility({ status: 'loaded', checks });
      })
      .catch((err) => {
        if (cancelled) return;
        setCompatibility({ status: Number((err as { status?: unknown })?.status ?? 0) === 404 ? 'not_found' : 'error', checks: [] });
      });
    return () => { cancelled = true; };
  }, [config, session, callerTargetId]);
  const callerPolicy = callerPolicyId
    ? [...linkedPolicyState.items, ...data.testPolicies].find((item) => getString(item, ['id', 'policy_id'], '') === callerPolicyId) ?? null
    : null;
  const callerTarget = callerTargetId ? declaredTargets.find((item) => getString(item, ['id'], '') === callerTargetId) ?? null : null;
  const callerBackHref = callerPolicyId ? buildDetailHref('policy-detail', callerPolicyId) : callerTargetId ? buildDetailHref('target-detail', callerTargetId) : '#checks';
  const callerBackLabel = callerPolicyId ? 'Back to schedule' : callerTargetId ? 'Back to target' : 'Check library';

  if (!entityId) {
    return (
      <div className="content">
        <DetailPageIntro route="check-detail" eyebrow="Check" />
        <EmptyState
          icon={FileCheck2}
          title="No check selected."
          body="This address does not name a check. Choose one from the check library."
          actionLabel="Open check library"
          actionHref="#checks"
        />
      </div>
    );
  }

  const exactReady = exactCheck.id === entityId;
  const check = exactReady && exactCheck.status === 'found' ? exactCheck.check : null;

  if (!check) {
    if (!exactReady || exactCheck.status === 'loading') {
      return (
        <div className="content">
          <DetailPageIntro route="check-detail" eyebrow="Check" />
          <DetailLoadingPlaceholder label="Loading check…" variant="layout" />
        </div>
      );
    }
    return (
      <div className="content">
        <DetailPageIntro route="check-detail" eyebrow="Check" />
        {exactCheck.status === 'error' ? (
          <EmptyState
            icon={TriangleAlert}
            title="Check could not be loaded."
            body={`${exactCheck.error} Check ${entityId} may still exist; nothing else is shown in its place.`}
            actionLabel="Retry"
            onAction={() => setExactCheckTick((count) => count + 1)}
          />
        ) : (
          <EmptyState
            icon={FileCheck2}
            title="Check not found."
            body={`No check with ID ${entityId} is in the catalog. It may have been removed or renamed; no other check is substituted.`}
            actionLabel={callerBackLabel === 'Check library' ? 'Open check library' : callerBackLabel}
            actionHref={callerBackHref}
          />
        )}
      </div>
    );
  }

  const family = getString(check, ['vector_family', 'family'], '');
  const safetyClass = getString(check, ['safety_class'], '');
  const execution = checkExecutionSemantics(check);
  const customerRunnable = safetyClass === 'safe';
  const description = getString(check, ['description', 'summary'], '');
  const title = plainCheckName(getString(check, ['name', 'check_id', 'id'], entityId));
  const toList = catalogValueList;
  const humanize = (value: string) => value.replace(/_/g, ' ');
  const recordedRemediation = getString(check, ['remediation_template', 'remediation'], '');
  const recordedVerdictLogic = getString(check, ['verdict_logic'], '');
  const recordedExplanation = getString(check, ['explanation_template', 'explanation'], '');
  const remediation = recordedRemediation === GENERIC_CHECK_REMEDIATION
    ? executionSpecificCheckCopy('remediation', execution)
    : recordedRemediation;
  const verdictLogic = recordedVerdictLogic === GENERIC_CHECK_VERDICT_LOGIC
    ? executionSpecificCheckCopy('verdict', execution)
    : recordedVerdictLogic;
  const explanation = recordedExplanation === GENERIC_CHECK_EXPLANATION
    ? executionSpecificCheckCopy('explanation', execution)
    : recordedExplanation;
  const expectedBehavior = getString(check, ['default_expected_behavior'], '');
  const supportedTargets = toList(check.supported_targets);
  const prerequisites = toList(check.prerequisites);
  const customerSetup = toList(check.required_customer_setup);
  const evidenceRequired = toList(check.evidence_required);
  const stopConditions = toList(check.stop_conditions);
  const pluralResources = toList(check.exhausted_resources);
  const taxonomyRows = [
    { label: 'Attack vectors', prefix: 'ATT', values: toList(check.attack_vector_ids) },
    { label: 'Exhausted resources', prefix: 'Resource', values: pluralResources.length > 0 ? pluralResources : toList(check.exhausted_resource) },
    { label: 'Delivery patterns', prefix: 'Pattern', values: toList(check.delivery_patterns) },
    { label: 'WAF vulnerabilities', prefix: 'WV', values: toList(check.waf_vulnerability_ids) },
    { label: 'Non-DDoS threats', prefix: 'ND', values: toList(check.non_ddos_threat_ids) }
  ];
  const maxEvents = getNestedNumber(check, ['safety_constraints', 'max_events'], 0);
  const maxDuration = getNestedNumber(check, ['safety_constraints', 'max_duration_seconds'], 0);
  const maxConcurrent = getNestedNumber(check, ['safety_constraints', 'max_concurrent_runs_per_target_group'], 0);
  const probeKind = getNestedString(check, ['probe_profile', 'kind'], '');
  const probeRequests = getNestedNumber(check, ['probe_profile', 'max_requests'], 0);
  const probeTimeout = getNestedNumber(check, ['probe_profile', 'timeout_ms'], 0);

  const recordedRuns = [...checkRunState.items]
    .sort((left, right) => String(right.completed_at ?? right.updated_at ?? right.created_at ?? '').localeCompare(String(left.completed_at ?? left.updated_at ?? left.created_at ?? '')));
  const latestResult = recordedRuns.find((run) => hasEvidenceBackedVerdict(run, data.evidence) && runVerdictValue(run)) ?? null;
  const latestAt = latestResult ? String(latestResult.completed_at ?? latestResult.updated_at ?? latestResult.created_at ?? '') : '';
  const latestAgeDays = latestAt ? Math.floor((Date.now() - Date.parse(latestAt)) / 86_400_000) : null;
  const latestTargetId = latestResult ? getString(latestResult, ['target_id'], '') : '';
  const targetLabel = (targetId: string) => {
    const match = declaredTargets.find((item) => getString(item, ['id'], '') === targetId);
    return getString(match ?? {}, ['value', 'hostname'], targetId);
  };
  const callerTargetKind = callerTarget ? effectivePolicyTargetKind(callerTarget) : '';
  const callerCompatible = compatibility.status === 'loaded'
    ? compatibility.checks.some((candidate) => getString(candidate, ['check_id'], '') === entityId)
    : null;
  const callerGroupId = callerTarget ? getString(callerTarget, ['target_group_id'], '') : '';
  const scheduleHref = `#test-policies?check=${encodeURIComponent(entityId)}${callerTarget && callerCompatible && callerGroupId ? `&group=${encodeURIComponent(callerGroupId)}&target=${encodeURIComponent(callerTargetId)}` : ''}`;
  const canSchedule = customerRunnable && sessionHasPermission(session, 'test_policy:write') && (!callerTargetId || callerCompatible === true);

  const policyColumns: TableColumn<DataItem>[] = [
    { key: 'target', label: 'Exact target', render: (item) => {
      const target = scheduleTarget(item);
      return target.targetId ? <DetailEntityLink route="target-detail" id={target.targetId} label={target.targetLabel} /> : <span className="muted">No exact target</span>;
    } },
    { key: 'cadence', label: 'Cadence', render: (item) => formatStatusLabel(getString(item, ['cadence'], ''), 'Not recorded') },
    { key: 'dispatch', label: 'Dispatch', render: (item) => <ScheduleStateBadge dispatch={describeScheduleDispatch(item, data.checks)} /> }
  ];
  const checkRunColumns: TableColumn<DataItem>[] = [
    { key: 'target', label: 'Target', render: (item) => {
      const runTargetId = getString(item, ['target_id'], '');
      return runTargetId ? <DetailEntityLink route="target-detail" id={runTargetId} label={targetLabel(runTargetId)} /> : <span className="muted">Not recorded</span>;
    } },
    { key: 'observed', label: 'Observed', render: (item) => <span className="mono">{formatDate(item.completed_at ?? item.updated_at ?? item.created_at)}</span> },
    { key: 'outcome', label: 'Outcome', render: (item) => {
      const outcome = hasEvidenceBackedVerdict(item, data.evidence) ? runVerdictValue(item) : '';
      return outcome
        ? <VerdictBadge value={outcome} tone={outcomeBadgeTone(outcome)} />
        : <span className="muted">{['planned', 'running', 'collecting'].includes(getString(item, ['status'], '')) ? 'In progress' : 'No evidence-backed result'}</span>;
    } },
    { key: 'evidence', label: 'Evidence', render: (item) => <RunEvidenceButton run={item} /> }
  ];

  return (
    <div className="content">
      <CustomerPageStyles />
      <DetailPageHeader
        route="check-detail"
        eyebrow="Check"
        entityId={entityId}
        title={title}
        actions={(
          <>
            <AnchorButton size="sm" variant="secondary" href={callerBackHref}>{callerBackLabel}</AnchorButton>
            {canSchedule ? (
              <AnchorButton size="sm" variant="default" href={scheduleHref}>
                {callerTarget ? `Schedule on ${targetLabel(callerTargetId)}` : 'Schedule this check'}
              </AnchorButton>
            ) : null}
          </>
        )}
      />
      {callerPolicyId || callerTargetId ? (
        <div className="form-banner neutral check-caller-context" role="note">
          {callerPolicyId ? (
            <span>Opened from schedule <a href={buildDetailHref('policy-detail', callerPolicyId)}>{callerPolicy ? scheduleDisplayName(callerPolicy, data.checks) : callerPolicyId}</a>.</span>
          ) : null}
          {callerTargetId ? (
            callerTarget ? (
              <span>
                {' '}Target <strong className="mono">{targetLabel(callerTargetId)}</strong> ({callerTargetKind.replace(/_/g, ' ') || 'kind not recorded'}):{' '}
                {compatibility.status === 'loading' ? 'checking compatibility…'
                  : compatibility.status === 'error' ? 'compatibility could not be loaded, so scheduling from here is not offered.'
                    : compatibility.status === 'not_found' ? 'this target is not visible in this workspace.'
                      : callerCompatible ? 'this check is compatible with it (launch gates are evaluated only when a run starts).' : `not compatible; this check runs on ${supportedTargets.join(', ') || 'no declared kind'}.`}
                {' '}Recorded results below are for this target only.
              </span>
            ) : <span> Target {callerTargetId} is not visible in this workspace; results are not filtered by it.</span>
          ) : null}
        </div>
      ) : null}
      {!customerRunnable ? (
        <div className="form-banner neutral" role="note">
          {safetyClass === 'soc_gated'
            ? 'This catalog entry is SOC-governed. It cannot be started or scheduled by customers in this release.'
            : 'This check is not marked customer-runnable, so it cannot be scheduled.'}
        </div>
      ) : null}

      <Card>
        <CardHeader>
          <CardTitle>What this check does</CardTitle>
          <CardDescription>{description || 'No check-specific description is recorded in the catalog.'}</CardDescription>
        </CardHeader>
        <CardContent className="check-explainer">
          <div>
            <p className="check-fact-label">What is sent</p>
            <p className="check-detail-text"><strong>{execution.kind}</strong>{probeKind ? <span className="muted"> · {plainCodeLabel(probeKind)}</span> : null}</p>
            <p className="check-detail-text">{execution.cap}</p>
            {probeTimeout ? <p className="muted small">{formatNumber(probeTimeout)} ms timeout</p> : null}
          </div>
          <div>
            <p className="check-fact-label">What is observed</p>
            <p className="check-detail-text">
              {evidenceRequired.length ? evidenceRequired.map(humanize).join(', ') : 'Evidence types not recorded in the catalog.'}
            </p>
          </div>
          <div>
            <p className="check-fact-label">How it is evaluated</p>
            <p className="check-detail-text">
              {verdictLogic || explanation || 'Evaluation rule not recorded.'}
              {expectedBehavior ? <> Expected behavior: <strong title={expectedBehavior}>{plainCodeLabel(expectedBehavior).toLowerCase()}</strong>.</> : null}
            </p>
          </div>
          <p className="muted small full">A bounded check proves one recorded behavior on one target. It does not establish volumetric capacity or protection for other targets.</p>
        </CardContent>
      </Card>

      <div className="dash-grid">
        <Card>
          <CardHeader>
            <CardTitle>Where it can run</CardTitle>
            <CardDescription>Catalog compatibility, not permission to run now. Ownership and rate gates apply at start.</CardDescription>
          </CardHeader>
          <CardContent className="stack-tight">
            <div>
              <p className="check-fact-label">Target kinds</p>
              {supportedTargets.length ? <div className="row-actions">{supportedTargets.map((kind) => <Badge key={kind} tone="muted">{humanize(kind)}</Badge>)}</div> : <p className="muted">Not recorded</p>}
            </div>
            <div>
              <p className="check-fact-label">Required setup</p>
              {customerSetup.length || prerequisites.length
                ? <ul className="check-detail-list">{[...customerSetup, ...prerequisites].map((item) => <li key={item}>{humanize(item)}</li>)}</ul>
                : <p className="muted">None recorded</p>}
            </div>
            <div>
              <p className="check-fact-label">Safety bounds</p>
              {maxEvents || maxDuration || maxConcurrent || probeRequests ? (
                <div className="stack-tight">
                  {probeRequests ? <p className="check-detail-text">{checkProbeOperationBoundLabel(probeRequests)}</p> : null}
                  <div className="row-actions">
                  {maxEvents ? <Badge tone="muted">max {maxEvents} events</Badge> : null}
                  {maxDuration ? <Badge tone="muted">max {maxDuration}s</Badge> : null}
                  {maxConcurrent ? <Badge tone="muted">{maxConcurrent} concurrent per group</Badge> : null}
                  </div>
                </div>
              ) : <p className="muted">Not recorded</p>}
            </div>
            {stopConditions.length ? (
              <div>
                <p className="check-fact-label">Stops when</p>
                <ul className="check-detail-list">{stopConditions.map((item) => <li key={item}>{humanize(item)}</li>)}</ul>
              </div>
            ) : null}
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>{callerTarget ? `Latest result on ${targetLabel(callerTargetId)}` : 'Latest recorded result'}</CardTitle>
            <CardDescription>A result belongs to one target at one time. It says nothing about other targets.</CardDescription>
          </CardHeader>
          <CardContent className="stack-tight">
            {checkRunState.status === 'loading' || checkRunState.status === 'idle' ? (
              <DetailLoadingPlaceholder label="Loading recorded results…" variant="compact" />
            ) : checkRunState.status === 'error' ? (
              <div className="form-banner error row-actions" role="alert">
                <span>Results unavailable: {checkRunState.error}</span>
                <Button size="sm" variant="secondary" onClick={() => setRunReload((count) => count + 1)}>Retry</Button>
              </div>
            ) : latestResult ? (
              <>
                <div className="row-actions">
                  <VerdictBadge value={runVerdictValue(latestResult)} tone={outcomeBadgeTone(runVerdictValue(latestResult))} />
                  <span>on {latestTargetId ? <DetailEntityLink route="target-detail" id={latestTargetId} label={targetLabel(latestTargetId)} /> : 'an unrecorded target'}</span>
                </div>
                <p className="muted small">
                  Observed {formatDate(latestAt)}{latestAgeDays !== null && latestAgeDays >= 30 ? ` · ${formatNumber(latestAgeDays)} days old, may no longer reflect current protection` : ''}
                </p>
                <div><RunEvidenceButton run={latestResult} /></div>
              </>
            ) : (
              <p className="muted">No evidence-backed result recorded{callerTarget ? ' for this target' : ''}. Not checked is not a pass.</p>
            )}
          </CardContent>
        </Card>
      </div>

      {remediation ? (
        <Card>
          <CardHeader>
            <CardTitle>If this check reports a gap</CardTitle>
            <CardDescription>Catalog guidance for this check; inspect the specific result's evidence first.</CardDescription>
          </CardHeader>
          <CardContent>
            <p className="check-detail-text">{remediation}</p>
          </CardContent>
        </Card>
      ) : null}

      <div className="stack">
        <Card>
          <CardHeader>
            <CardTitle>Schedules running this check</CardTitle>
            <CardDescription>Schedules bound to this exact check ID.</CardDescription>
          </CardHeader>
          <CardContent>
            <DataTable
              columns={policyColumns}
              items={linkedPolicyState.items}
              getRowId={(item) => getString(item, ['id', 'policy_id'], '')}
              getRowProps={(item) => detailRowNavProps('policy-detail', getString(item, ['id', 'policy_id'], ''))}
              loadError={linkedPolicyState.status === 'error' ? linkedPolicyState.error : null}
              onRetry={() => setPolicyReload((count) => count + 1)}
              empty={linkedPolicyState.status === 'loading' || linkedPolicyState.status === 'idle'
                ? <DetailLoadingPlaceholder label="Loading linked schedules…" variant="compact" />
                : <EmptyState icon={ClipboardList} title="No schedules run this check." body="Nothing dispatches this check automatically." actionLabel={canSchedule ? 'Schedule this check' : undefined} actionHref={canSchedule ? scheduleHref : undefined} />}
            />
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>Recorded results</CardTitle>
            <CardDescription>Up to 25 recent runs of this check{callerTarget ? ' on this target' : ''}. Select one to see its evidence here.</CardDescription>
          </CardHeader>
          <CardContent>
            <DataTable
              columns={checkRunColumns}
              items={recordedRuns.slice(0, 25)}
              getRowId={(item) => getString(item, ['id'], '')}
              getRowProps={(item) => checkResultInspectorRowProps(item, `View evidence for ${targetLabel(getString(item, ['target_id'], ''))} at ${formatDate(item.completed_at ?? item.updated_at ?? item.created_at)}`)}
              loadError={checkRunState.status === 'error' ? checkRunState.error : null}
              onRetry={() => setRunReload((count) => count + 1)}
              empty={checkRunState.status === 'loading' || checkRunState.status === 'idle'
                ? <DetailLoadingPlaceholder label="Loading recorded results…" variant="compact" />
                : <EmptyState icon={Activity} title="No recorded runs." body={callerTarget ? 'This check has not run on this target.' : 'This check has not run in this workspace.'} />}
            />
          </CardContent>
        </Card>
      </div>

      <details className="detail-technical">
        <summary>Technical details</summary>
        <div className="stack">
          <div className="kv-list">
            <div><span>Check ID</span><strong className="mono">{entityId}</strong></div>
            <div><span>Family</span><strong>{formatCheckFamilyLabel(family)}</strong></div>
            <div><span>Mode</span><strong>{formatCheckModeLabel(safetyClass)}</strong></div>
            {explanation && verdictLogic ? <div><span>Explanation</span><strong>{explanation}</strong></div> : null}
          </div>
          <p className="muted small">Catalog identifiers recorded for this check. Values are shown as stored, without broadening or truncation.</p>
          {taxonomyRows.map((row) => (
            <div key={row.label}>
              <p className="check-fact-label">{row.label}</p>
              {row.values.length > 0 ? (
                <div className="row-actions">
                  {row.values.map((value) => <Badge key={`${row.label}-${value}`} tone="muted" title={value}>{value.includes('_') ? plainCodeLabel(value) : value}</Badge>)}
                </div>
              ) : <p className="muted">No {row.prefix} identifiers recorded.</p>}
            </div>
          ))}
        </div>
      </details>
    </div>
  );
}

/** Row activation that opens the shared evidence inspector for one exact check result. */
function checkResultInspectorRowProps(run: DataItem, label: string): Omit<HTMLAttributes<HTMLTableRowElement>, 'key'> {
  const ref = {
    entry: 'check_result' as const,
    target_id: getString(run, ['target_id'], ''),
    check_id: getString(run, ['check_id'], ''),
    test_run_id: getString(run, ['id', 'test_run_id', 'run_id'], '')
  };
  if (!ref.target_id || !ref.check_id || !ref.test_run_id) return {};
  const open = () => { openEvidenceInspector(ref, { focusKey: ref.test_run_id }); };
  return {
    tabIndex: 0,
    style: { cursor: 'pointer' },
    'aria-label': label,
    'data-focus-key': ref.test_run_id,
    onClick: (event) => {
      if ((event.target as HTMLElement).closest('a, button')) return;
      open();
    },
    onKeyDown: (event: KeyboardEvent<HTMLTableRowElement>) => {
      if (event.target !== event.currentTarget) return;
      if (event.key === 'Enter' || event.key === ' ') {
        event.preventDefault();
        open();
      }
    }
  } as Omit<HTMLAttributes<HTMLTableRowElement>, 'key'>;
}

function RunEvidenceButton({ run }: { run: DataItem }) {
  const ref = {
    entry: 'check_result' as const,
    target_id: getString(run, ['target_id'], ''),
    check_id: getString(run, ['check_id'], ''),
    test_run_id: getString(run, ['id', 'test_run_id', 'run_id'], '')
  };
  if (!ref.target_id || !ref.check_id || !ref.test_run_id) return <span className="muted small">Target or check not recorded</span>;
  return (
    <Button size="sm" variant="ghost" onClick={() => openEvidenceInspector(ref, { focusKey: ref.test_run_id })}>
      View evidence
    </Button>
  );
}

function PolicyDetailPage({
  entityId,
  data,
  config,
  session,
  onRefresh
}: {
  entityId: string;
  data: PortalData;
  config: PortalConfig;
  session: Session;
  onRefresh: () => Promise<void>;
}) {
  const [feedback, setFeedback] = useState<{ message: string; error: string }>({ message: '', error: '' });
  const [runRelationState, setRunRelationState] = useState<{
    status: 'idle' | 'loading' | 'loaded' | 'error';
    items: DataItem[];
    error: string;
    scanned: number;
  }>({ status: 'idle', items: [], error: '', scanned: 0 });
  const [historyReload, setHistoryReload] = useState(0);
  const canWrite = sessionHasPermission(session, 'test_policy:write');

  useEffect(() => {
    if (!entityId) {
      setRunRelationState({ status: 'idle', items: [], error: '', scanned: 0 });
      return;
    }
    let cancelled = false;
    setRunRelationState((current) => ({ ...current, status: 'loading', error: '' }));
    requestJson(config, session, '/v1/test-runs?limit=100')
      .then((payload) => {
        if (cancelled) return;
        if (!payload || typeof payload !== 'object' || Array.isArray(payload) || !Array.isArray((payload as { items?: unknown }).items)) {
          throw new Error('Invalid test-run list response.');
        }
        const items = (payload as { items: unknown[] }).items;
        if (!items.every((item) => item && typeof item === 'object' && !Array.isArray(item))) {
          throw new Error('Invalid test-run records.');
        }
        const policyRuns = (items as DataItem[])
          .filter((run) => getString(run, ['policy_id', 'test_policy_id'], '') === entityId)
          .sort((left, right) => String(right.updated_at ?? right.created_at ?? '').localeCompare(String(left.updated_at ?? left.created_at ?? '')));
        setRunRelationState({ status: 'loaded', items: policyRuns, error: '', scanned: items.length });
      })
      .catch((err) => {
        if (!cancelled) {
          setRunRelationState({ status: 'error', items: [], error: err instanceof Error ? err.message : 'Could not load dispatch history.', scanned: 0 });
        }
      });
    return () => { cancelled = true; };
  }, [config, session, entityId, historyReload]);

  if (!entityId) {
    return (
      <div className="content">
        <DetailPageIntro route="policy-detail" eyebrow="Validation schedule" />
        <EmptyState
          icon={ClipboardList}
          title="No schedule selected."
          body="This address does not name a schedule. Open one from the validation schedule list."
          actionLabel="Open validation schedules"
          actionHref="#test-policies"
        />
      </div>
    );
  }

  const policy = data.testPolicies.find((item) => getString(item, ['id', 'policy_id'], '') === entityId) ?? null;

  if (!policy) {
    return (
      <div className="content">
        <DetailPageIntro route="policy-detail" eyebrow="Validation schedule" />
        {data.loadErrors.testPolicies ? (
          <EmptyState
            icon={TriangleAlert}
            title="Schedules could not be loaded."
            body={`${data.loadErrors.testPolicies} Schedule ${entityId} may still exist; nothing is shown in its place.`}
            actionLabel="Retry"
            onAction={() => void onRefresh()}
          />
        ) : (
          <EmptyState
            icon={ClipboardList}
            title="Schedule not found."
            body={`No schedule with ID ${entityId} is visible in this workspace. It may belong to another tenant or never existed.`}
            actionLabel="Open validation schedules"
            actionHref="#test-policies"
          />
        )}
      </div>
    );
  }

  const checks = data.checks;
  const title = scheduleDisplayName(policy, checks);
  const check = scheduleCheck(policy, checks);
  const target = scheduleTarget(policy);
  const dispatch = describeScheduleDispatch(policy, checks);
  const timezone = getString(policy, ['timezone'], '');
  const cadence = getString(policy, ['cadence'], '');
  const windows = scheduleSafeWindows(policy);
  const expected = getString(policy, ['expected_verdict'], '');
  const lastDispatchedAt = getString(policy, ['last_dispatched_at'], '');
  const safetySnapshot = getNestedItem(policy, ['safety_policy_snapshot']);
  const next = dispatch.nextRunAt ? formatScheduleInstant(dispatch.nextRunAt, timezone) : null;
  const checkHref = scheduleCheckHref(policy, checks);
  const binding = evidenceCodeBlock([
    ['policy_id', entityId],
    ['target_group_id', target.groupId],
    ['target_id', target.targetId],
    ['check_id', check.checkId],
    ['cadence', cadence],
    ['timezone', timezone],
    ['expected_verdict', expected],
    ['state', getString(policy, ['state'], '')],
    ['enabled', policy.enabled === undefined ? '' : String(policy.enabled)],
    ['next_run_at', getString(policy, ['next_run_at'], '')],
    ['schedule_revision', getString(policy, ['schedule_revision'], '')]
  ]);
  const state = getString(policy, ['state'], '');
  const gates: Array<{ label: string; status: 'met' | 'blocked' | 'info'; detail: string }> = [
    {
      label: 'Exact target bound',
      status: target.targetId ? 'met' : 'blocked',
      detail: target.targetId ? `${target.targetLabel}${target.groupLabel ? ` in ${target.groupLabel}` : ''}` : 'Legacy schedule without an exact target. Create a new schedule bound to one target.'
    },
    {
      label: 'Check available and customer-runnable',
      status: !check.checkId || (checks.length > 0 && !check.inCatalog) || getString(check.record, ['safety_class'], '') === 'soc_gated' ? 'blocked' : 'met',
      detail: !check.checkId
        ? 'The schedule does not record a check.'
        : checks.length > 0 && !check.inCatalog
          ? `Check ${check.checkId} is not in the current catalog.`
          : getString(check.record, ['safety_class'], '') === 'soc_gated'
            ? 'SOC-governed check; it cannot dispatch from a customer schedule.'
            : check.name
    },
    {
      label: 'Active and enabled',
      status: state === 'active' && policy.enabled !== false ? 'met' : 'blocked',
      detail: !state
        ? 'State not recorded.'
        : state === 'active'
          ? policy.enabled === false ? 'Active but disabled; the scheduler skips it.' : 'Active.'
          : `${formatStatusLabel(state)}. ${state === 'paused' ? 'Resume to dispatch again.' : 'This state does not dispatch.'}`
    },
    {
      label: 'Automatic cadence',
      status: cadence && cadence !== 'manual' ? 'met' : 'blocked',
      detail: !cadence ? 'Cadence not recorded.' : cadence === 'manual' ? 'Manual cadence never dispatches automatically. Edit the schedule to choose daily, weekly, or monthly.' : `${formatStatusLabel(cadence)} in ${timezone || 'UTC (timezone not recorded)'}.`
    },
    {
      label: 'Next run recorded by the scheduler',
      status: dispatch.nextRunAt ? 'met' : dispatch.bucket === 'blocked' && state === 'active' && cadence !== 'manual' ? 'blocked' : 'info',
      detail: next ? `${next.primary} ${next.zone}` : dispatch.reason
    },
    {
      label: 'Safe window',
      status: 'info',
      detail: windows.length === 0 ? 'No window: runs can start any time on the cadence.' : `Runs start only within ${formatSafeWindowList(policy)}.`
    }
  ];
  const runColumns: TableColumn<DataItem>[] = [
    { key: 'recorded', label: 'Dispatched', render: (run) => <span className="mono">{formatDate(run.started_at ?? run.created_at)}</span> },
    { key: 'target', label: 'Target', render: (run) => {
      const runTargetId = getString(run, ['target_id'], '');
      return runTargetId ? <DetailEntityLink route="target-detail" id={runTargetId} label={runTargetId === target.targetId ? target.targetLabel : runTargetId} /> : <span className="muted">Not recorded</span>;
    } },
    { key: 'status', label: 'Status', render: (run) => <StatusBadge value={getString(run, ['status'], '')} tone={runStatusBadgeTone(getString(run, ['status'], ''))} fallback="Not recorded" /> },
    { key: 'outcome', label: 'Outcome', render: (run) => {
      const outcome = hasEvidenceBackedVerdict(run, data.evidence) ? runVerdictValue(run) : '';
      return outcome ? <VerdictBadge value={outcome} tone={outcomeBadgeTone(outcome)} /> : <span className="muted">No evidence-backed result</span>;
    } },
    { key: 'evidence', label: 'Evidence', render: (run) => <RunEvidenceButton run={run} /> }
  ];

  return (
    <div className="content">
      <CustomerPageStyles />
      <DetailPageHeader
        route="policy-detail"
        eyebrow="Validation schedule"
        entityId={entityId}
        title={title}
        actions={(
          <>
            <AnchorButton size="sm" variant="ghost" href="#test-policies">All schedules</AnchorButton>
            <ScheduleActions
              policy={policy}
              checks={checks}
              config={config}
              session={session}
              canWrite={canWrite}
              onChanged={async (message) => {
                setFeedback({ message, error: '' });
                await onRefresh();
                setHistoryReload((count) => count + 1);
              }}
              onError={(error) => setFeedback({ message: '', error })}
            />
          </>
        )}
      />
      {feedback.message || feedback.error ? (
        <div className={feedback.error ? 'form-banner error' : 'form-banner neutral'} role={feedback.error ? 'alert' : 'status'}>{feedback.error || feedback.message}</div>
      ) : null}
      {!canWrite ? <p className="muted small">Read only. Editing, pausing, or archiving requires the test_policy:write permission.</p> : null}
      <Card className="schedule-dispatch-card">
        <CardHeader>
          <CardTitle>Will this schedule run?</CardTitle>
          <CardDescription>From the recorded schedule only. Configuration is not execution proof; gates are rechecked at dispatch.</CardDescription>
        </CardHeader>
        <CardContent className="stack-tight">
          <div className="row-actions">
            <ScheduleStateBadge dispatch={dispatch} />
            <span>{dispatch.reason}</span>
          </div>
          <div className="kv-list">
            <div><span>Next run</span><strong>{next ? <>{next.primary} <span className="muted">{next.zone}</span></> : 'No next run recorded'}</strong></div>
            {next?.viewer ? <div><span>In your timezone</span><strong>{next.viewer}</strong></div> : null}
            <div><span>Last dispatched</span><strong>{lastDispatchedAt ? formatDate(lastDispatchedAt) : 'Never dispatched'}</strong></div>
          </div>
        </CardContent>
      </Card>
      <div className="dash-grid">
        <Card>
          <CardHeader>
            <CardTitle>Bound target and check</CardTitle>
            <CardDescription>Immutable after creation. A different target or check needs a new schedule.</CardDescription>
          </CardHeader>
          <CardContent className="kv-list">
            <div><span>Check</span>{checkHref ? <a href={checkHref}>{check.name}</a> : <strong>Not recorded</strong>}</div>
            <div><span>Exact target</span>{target.targetId ? <DetailEntityLink route="target-detail" id={target.targetId} label={target.targetLabel} /> : <strong>Not recorded</strong>}</div>
            <div><span>Target group</span>{target.groupId ? <DetailEntityLink route="target-group-detail" id={target.groupId} label={target.groupLabel} /> : <strong>Not recorded</strong>}</div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>Timing and expectation</CardTitle>
            <CardDescription>Fields recorded on the schedule.</CardDescription>
          </CardHeader>
          <CardContent className="kv-list">
            <div><span>Cadence</span><strong>{cadence ? formatStatusLabel(cadence) : 'Not recorded'}</strong></div>
            <div><span>Timezone</span><strong>{timezone || 'Not recorded (scheduler default UTC)'}</strong></div>
            <div><span>Safe windows</span><strong>{windows.length ? formatSafeWindowList(policy) : 'None (any time)'}</strong></div>
            <div><span>Expected verdict</span><strong>{expected ? `${plainVerdictLabel(expected)} (declared)` : 'Not recorded'}</strong></div>
            <div><span>Created</span><strong>{formatDate(policy.created_at)}</strong></div>
            <div><span>Updated</span><strong>{formatDate(policy.updated_at)}</strong></div>
          </CardContent>
        </Card>
      </div>
      <Card>
        <CardHeader>
          <CardTitle>Dispatch gates</CardTitle>
          <CardDescription>What must hold for the scheduler to dispatch. Ownership, rate, and concurrency are still checked server-side at dispatch.</CardDescription>
        </CardHeader>
        <CardContent>
          <ul className="placement-gates" aria-label="Schedule dispatch gates">
            {gates.map((gate) => (
              <li key={gate.label}>
                {gate.status === 'blocked' ? <TriangleAlert size={14} aria-hidden="true" /> : <ShieldCheck size={14} aria-hidden="true" />}
                <span>{gate.label}<span className="muted small"> · {plainInlineText(gate.detail)}</span></span>
                <Badge tone={gate.status === 'met' ? 'success' : gate.status === 'blocked' ? 'warn' : 'muted'}>
                  {gate.status === 'met' ? 'Met' : gate.status === 'blocked' ? 'Blocks dispatch' : 'Info'}
                </Badge>
              </li>
            ))}
          </ul>
        </CardContent>
      </Card>
      <Card>
        <CardHeader>
          <CardTitle>Dispatch history</CardTitle>
          <CardDescription>
            Runs that record this schedule ID, searched within {runRelationState.scanned ? `the ${formatNumber(runRelationState.scanned)} most recent run${runRelationState.scanned === 1 ? '' : 's'}` : 'the most recent runs'} returned. Select a run to inspect its evidence here.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <DataTable
            columns={runColumns}
            items={runRelationState.items}
            getRowId={(run) => getString(run, ['id'], '')}
            getRowProps={(run) => checkResultInspectorRowProps(run, `View evidence for run dispatched ${formatDate(run.started_at ?? run.created_at)}`)}
            loadError={runRelationState.status === 'error' ? runRelationState.error : null}
            onRetry={() => setHistoryReload((count) => count + 1)}
            empty={runRelationState.status === 'loading' || runRelationState.status === 'idle'
              ? <DetailLoadingPlaceholder label="Loading dispatch history…" variant="compact" />
              : <EmptyState icon={Activity} title="No dispatches recorded." body={lastDispatchedAt ? 'The schedule records a dispatch, but its run is outside the returned recent-run window.' : 'This schedule has not dispatched a run yet.'} />}
          />
        </CardContent>
      </Card>
      <details className="detail-technical">
        <summary>Technical record</summary>
        {binding ? <DetailCodeBlock label="Schedule binding record">{binding}</DetailCodeBlock> : null}
        {safetySnapshot ? <DetailCodeBlock label="Safety snapshot captured at creation">{JSON.stringify(safetySnapshot, null, 2)}</DetailCodeBlock> : null}
      </details>
    </div>
  );
}

export function DetailRoutePage({
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
  const [runEventState, setRunEventState] = useState<RunEventEvidenceState>({
    entityId: '',
    status: 'loading',
    items: [],
    error: ''
  });
  // Re-read id when hash changes even if route id stays the same (e.g. queue-detail?id=A → id=B).
  const [routeQueryTick, setRouteQueryTick] = useState(0);
  useEffect(() => {
    function onHashChange() {
      setRouteQueryTick((n) => n + 1);
    }
    window.addEventListener('hashchange', onHashChange);
    return () => window.removeEventListener('hashchange', onHashChange);
  }, []);
  const entityId = useMemo(() => getRouteEntityId(''), [route, routeQueryTick]);
  const visibleRunEventState: RunEventEvidenceState =
    route === 'run-detail' && entityId && runEventState.entityId === entityId
      ? runEventState
      : { entityId, status: 'loading', items: [], error: '' };

  const targetGroupFallback = data.targetGroups.find((item) => getString(item, ['id'], '') === entityId) ?? null;
  const runFallback = data.runs.find((item) => getString(item, ['id'], '') === entityId) ?? null;
  const tenantFallback = data.internalTenants.find((item) => getString(item, ['tenant_id', 'id'], '') === entityId) ?? null;
  const findingFallback = data.findings.find((item) => getString(item, ['id'], '') === entityId) ?? null;
  const highScaleFallback = data.highScale.find((item) => getString(item, ['id'], '') === entityId) ?? null;

  const targetGroupDetail = useEntityDetail(
    route === 'target-group-detail' && Boolean(entityId),
    config,
    session,
    `/v1/target-groups/${encodeURIComponent(entityId)}`,
    targetGroupFallback
  );
  const runDetail = useEntityDetail(
    route === 'run-detail' && Boolean(entityId),
    config,
    session,
    `/v1/test-runs/${encodeURIComponent(entityId)}`,
    runFallback
  );
  const tenantDetail = useEntityDetail(
    route === 'tenant-detail' && Boolean(entityId) && session.principal === 'staff',
    config,
    session,
    `/internal/admin/tenants/${encodeURIComponent(entityId)}`,
    null
  );
  const findingDetailState = useEntityDetail(
    route === 'finding-detail' && Boolean(entityId),
    config,
    session,
    `/v1/findings/${encodeURIComponent(entityId)}`,
    findingFallback
  );
  // Mutations on an entity detail page must re-read the entity itself, not just the list
  // datasets onRefresh reloads; otherwise removed targets, triage changes, etc. stay on screen.
  const activeEntityReload = route === 'target-group-detail'
    ? targetGroupDetail.reload
    : route === 'run-detail'
      ? runDetail.reload
      : route === 'tenant-detail'
        ? tenantDetail.reload
        : route === 'finding-detail'
          ? findingDetailState.reload
          : null;
  const refreshWithEntity = useCallback(async () => {
    await Promise.all([onRefresh(), activeEntityReload ? activeEntityReload() : Promise.resolve()]);
  }, [onRefresh, activeEntityReload]);
  const queueTenantId = useMemo(
    () => getRouteTenantId(session.tenant_id ?? '') || undefined,
    [route, entityId, session.tenant_id]
  );
  const highScaleDetail = useListBackedDetail(
    route === 'queue-detail' && Boolean(entityId),
    config,
    session,
    '/v1/high-scale-requests',
    entityId,
    highScaleFallback,
    {
      staffSoc: session.principal === 'staff' && isStaffSocRole(session),
      tenantId: queueTenantId
    }
  );
  const detailState =
    route === 'target-group-detail' ? targetGroupDetail
      : route === 'run-detail' ? runDetail
        : { detail: null as DataItem | null, error: '', loading: false };

  const entity =
    route === 'tenant-detail' ? tenantFallback
      : route === 'queue-detail' ? (highScaleDetail.detail ?? highScaleFallback)
        : detailState.detail;

  useEffect(() => {
    if (route !== 'run-detail' || !entityId) {
      setRunEventState({ entityId: '', status: 'loading', items: [], error: '' });
      return;
    }
    const requestedEntityId = entityId;
    let cancelled = false;
    setRunEventState({ entityId: requestedEntityId, status: 'loading', items: [], error: '' });
    requestJson(config, session, `/v1/test-runs/${encodeURIComponent(requestedEntityId)}/events`)
      .then((payload) => {
        if (cancelled) return;
        if (!payload || typeof payload !== 'object' || Array.isArray(payload) || !Array.isArray((payload as { items?: unknown }).items)) {
          throw new Error('Invalid run-events response.');
        }
        const items = (payload as { items: unknown[] }).items;
        if (!items.every((item) => item && typeof item === 'object' && !Array.isArray(item))) {
          throw new Error('Invalid run-events response.');
        }
        if ((items as DataItem[]).some((item) => {
          const eventRunId = getString(item, ['test_run_id'], '');
          return eventRunId !== '' && eventRunId !== requestedEntityId;
        })) {
          throw new Error('Run-events response contained cross-run records.');
        }
        setRunEventState({
          entityId: requestedEntityId,
          status: 'loaded',
          items: (payload as { items: DataItem[] }).items,
          error: ''
        });
      })
      .catch(() => {
        if (cancelled) return;
        setRunEventState({
          entityId: requestedEntityId,
          status: 'error',
          items: [],
          error: 'Run event evidence unavailable.'
        });
      });
    return () => { cancelled = true; };
  }, [route, entityId, config, session]);

  if (route === 'tenant-detail') {
    if (!entityId) {
      return (
        <div className="content">
          <DetailPageIntro route={route} eyebrow="Staff tenant operations" />
          <EmptyState icon={Target} title="No tenant selected." body="Open a tenant from the staff directory with ?id= or use the Detail link on #admin." actionLabel="Open staff admin" actionHref="#admin" />
        </div>
      );
    }
    if (session.principal !== 'staff') {
      return (
        <div className="content">
          <DetailPageIntro route={route} eyebrow="Staff tenant operations" />
          <EmptyState icon={UserCog} title="Staff session required." body="Tenant detail is available after staff sign-in." actionLabel="Open staff login" actionHref="/internal/admin/login" />
        </div>
      );
    }
    return (
      <TenantDetailView
        entityId={entityId}
        detail={tenantDetail.detail}
        data={data}
        config={config}
        session={session}
        onRefresh={refreshWithEntity}
        loading={tenantDetail.loading}
        loadError={tenantDetail.error}
      />
    );
  }

  if (route === 'finding-detail') {
    if (!entityId) {
      return (
        <div className="content">
          <DetailPageIntro route={route} eyebrow="Evidence-backed finding" />
          <EmptyState icon={TriangleAlert} title="No finding selected." body="Open a finding from the list with ?id= or use the View link on #findings." actionLabel="Open findings" actionHref="#findings" />
        </div>
      );
    }
    const findingEntity = findingDetailState.detail ?? findingFallback;
    if (!findingEntity && findingDetailState.loading) {
      return (
        <div className="content">
          <DetailPageIntro route={route} eyebrow="Evidence-backed finding" />
          <DetailLoadingPlaceholder label="Loading finding detail…" />
        </div>
      );
    }
    if (!findingEntity) {
      return (
        <div className="content">
          <DetailPageIntro route={route} eyebrow="Evidence-backed finding" />
          <EmptyState icon={TriangleAlert} title="Finding not found." body={findingDetailState.error || 'The requested finding is missing or outside this tenant scope.'} actionLabel="Open findings" actionHref="#findings" />
        </div>
      );
    }
    return (
      <FindingDetailViewRevamp
        entity={findingEntity}
        entityId={entityId}
        data={data}
        config={config}
        session={session}
        onRefresh={refreshWithEntity}
        loading={findingDetailState.loading}
        loadError={findingDetailState.error}
      />
    );
  }

  if (route === 'target-detail') {
    if (!entityId) {
      return (
        <div className="content">
          <DetailPageIntro route={route} eyebrow="Declared target" />
          <EmptyState icon={Target} title="No target selected." body="Open a target from a target group detail table." actionLabel="Open target groups" actionHref="#target-groups" />
        </div>
      );
    }
    return <TargetDetailView entityId={entityId} config={config} session={session} checks={data.checks} targetGroups={data.targetGroups} wafEdgeEnabled={data.deploymentFeatures?.waf_posture === true} onRefresh={onRefresh} />;
  }

  if (route === 'check-detail') {
    return <CheckDetailPage entityId={entityId} data={data} config={config} session={session} />;
  }

  if (route === 'policy-detail') {
    return <PolicyDetailPage entityId={entityId} data={data} config={config} session={session} onRefresh={onRefresh} />;
  }

  if (route === 'evidence-detail') {
    return <EvidenceDetailView data={data} config={config} session={session} />;
  }

  if (route === 'queue-detail') {
    const staffSocWorkspace = session.principal === 'staff' && isStaffSocRole(session);
    if (!entityId) {
      return (
        <div className="content">
          <DetailPageIntro route={route} eyebrow={staffSocWorkspace ? 'SOC execution workspace' : 'High-scale authorization pack'} />
          <EmptyState
            icon={ShieldCheck}
            title="No high-scale request selected."
            body={staffSocWorkspace
              ? 'Open a queue item from the SOC console with ?id=.'
              : 'Open a request from Test runs using Complete pack.'}
            actionLabel={staffSocWorkspace ? 'Open SOC console' : 'Open test runs'}
            actionHref={staffSocWorkspace ? '#internal-soc' : '#runs'}
          />
        </div>
      );
    }
    const queueEntity = highScaleDetail.detail ?? highScaleFallback;
    if (!queueEntity && highScaleDetail.loading) {
      return (
        <div className="content">
          <DetailPageIntro route={route} eyebrow={staffSocWorkspace ? 'SOC execution workspace' : 'High-scale authorization pack'} />
          <DetailLoadingPlaceholder label="Loading high-scale request…" />
        </div>
      );
    }
    if (!queueEntity) {
      return (
        <div className="content">
          <DetailPageIntro route={route} eyebrow={staffSocWorkspace ? 'SOC execution workspace' : 'High-scale authorization pack'} />
          <EmptyState
            icon={ShieldCheck}
            title="High-scale request not found."
            body={highScaleDetail.error || 'The requested high-scale item is missing or outside this tenant scope.'}
            actionLabel={staffSocWorkspace ? 'Open SOC console' : 'Open test runs'}
            actionHref={staffSocWorkspace ? '#internal-soc' : '#runs'}
          />
        </div>
      );
    }
    // Staff SOC: lifecycle / kill-switch workspace. Customer: multi-type authorization pack.
    if (staffSocWorkspace) {
      return (
        <SocRequestDetailView
          entity={queueEntity}
          entityId={entityId}
          config={config}
          session={session}
          onRefresh={onRefresh}
          tenantId={queueTenantId || getString(queueEntity, ['tenant_id'], '') || undefined}
        />
      );
    }
    return (
      <HighScaleDetailView
        entity={queueEntity}
        entityId={entityId}
        data={data}
        config={config}
        session={session}
        onRefresh={onRefresh}
        loading={highScaleDetail.loading}
        loadError={highScaleDetail.error}
      />
    );
  }

  if (route === 'target-group-detail') {
    if (!entityId) {
      return (
        <div className="content">
          <DetailPageIntro route={route} eyebrow="Declared business service" />
          <EmptyState
            icon={Target}
            title="No target group selected."
            body="Open a group from the list with ?id= or use the Detail link on #target-groups."
            actionLabel="Open target groups"
            actionHref="#target-groups"
          />
        </div>
      );
    }
    if (!entity && detailState.loading) {
      return (
        <div className="content">
          <DetailPageIntro route={route} eyebrow="Declared business service" />
          <DetailLoadingPlaceholder label="Loading target group detail…" />
        </div>
      );
    }
    if (!entity) {
      return (
        <div className="content">
          <DetailPageIntro route={route} eyebrow="Declared business service" />
          <EmptyState
            icon={Target}
            title="Target group not found."
            body={detailState.error || 'The requested group is missing, archived, or outside this tenant scope.'}
            actionLabel="Open target groups"
            actionHref="#target-groups"
          />
        </div>
      );
    }
    return (
      <TargetGroupDetailViewRevamp
        entity={entity}
        entityId={entityId}
        data={data}
        config={config}
        session={session}
        onRefresh={refreshWithEntity}
        loading={detailState.loading}
        loadError={detailState.error}
      />
    );
  }

  if (!entityId) {
    const noSelectionByRoute: Partial<Record<RouteId, { eyebrow: string; title: string; body: string; actionLabel: string; actionHref: string; icon: typeof Target }>> = {
      'run-detail': {
        eyebrow: 'Test run evidence',
        title: 'No test run selected.',
        body: 'Open a run from the list with ?id= or use the Detail link on #runs.',
        actionLabel: 'Open test runs',
        actionHref: '#runs',
        icon: Activity
      },
      'finding-detail': {
        eyebrow: 'Evidence-backed finding',
        title: 'No finding selected.',
        body: 'Open a finding from the list with ?id= or use the View link on #findings.',
        actionLabel: 'Open findings',
        actionHref: '#findings',
        icon: TriangleAlert
      },
      'queue-detail': {
        eyebrow: 'SOC execution workspace',
        title: 'No SOC request selected.',
        body: 'Open a queue item from Test runs or the SOC console with ?id=.',
        actionLabel: 'Open SOC console',
        actionHref: '#internal-soc',
        icon: ShieldCheck
      },
      'target-detail': {
        eyebrow: 'Declared target',
        title: 'No target selected.',
        body: 'Open a target from a target group detail table.',
        actionLabel: 'Open target groups',
        actionHref: '#target-groups',
        icon: Target
      }
    };
    const noSelection = noSelectionByRoute[route];
    return (
      <div className="content">
        <DetailPageIntro route={route} eyebrow={noSelection?.eyebrow ?? 'Detail surface'} />
        <EmptyState
          icon={noSelection?.icon ?? Target}
          title={noSelection?.title ?? 'No entity selected.'}
          body={noSelection?.body ?? 'Open a list row with ?id= or use the Detail link on the parent list page.'}
          actionLabel={noSelection?.actionLabel}
          actionHref={noSelection?.actionHref}
        />
      </div>
    );
  }

  if (!entity && detailState.loading) {
    return (
      <div className="content">
        <DetailPageIntro route={route} eyebrow="Entity detail" />
        <DetailLoadingPlaceholder label="Loading entity detail…" />
      </div>
    );
  }

  if (!entity) {
    const listHrefByRoute: Partial<Record<RouteId, { actionLabel: string; actionHref: string }>> = {
      'run-detail': { actionLabel: 'Open test runs', actionHref: '#runs' },
    };
    const listLink = listHrefByRoute[route];
    return (
      <div className="content">
        <DetailPageIntro route={route} eyebrow="Entity detail" />
        <EmptyState
          icon={Target}
          title="Entity not found."
          body={detailState.error || 'The requested record is missing or outside this tenant scope.'}
          actionLabel={listLink?.actionLabel}
          actionHref={listLink?.actionHref}
        />
      </div>
    );
  }

  if (route === 'run-detail') {
    return (
      <RunDetailView
        entity={entity}
        entityId={entityId}
        data={data}
        config={config}
        session={session}
        onRefresh={refreshWithEntity}
        runEventState={visibleRunEventState}
        loading={detailState.loading}
        loadError={detailState.error}
      />
    );
  }

  return (
    <div className="content">
      <DetailPageIntro route={route} eyebrow="Detail surface" />
      <EmptyState
        icon={Target}
        title="Unsupported detail route."
        body="This detail view is not available in the revamp navigation."
        actionLabel="Open dashboard"
        actionHref="#dashboard"
      />
    </div>
  );

}

type ReportCoverageRow = {
  id: string;
  name: string;
  runs: number;
  openFindings: number;
  verdict: string;
};

const RUN_ID_PATTERN = /^[A-Za-z0-9_.:-]{1,128}$/;
const LIVE_RUN_FINDINGS_LIMIT = 25;

/** Open findings now linked to a report's captured runs: one exact server predicate per run, never the loaded page. */
function ReportLiveOpenFindings({ data, config, session, runIds, checkedAt }: { data: PortalData; config: PortalConfig; session: Session; runIds: string[]; checkedAt: string }) {
  const readable = canReadDataset(session, 'findings');
  const validRunIds = useMemo(() => [...new Set(runIds)].filter((id) => RUN_ID_PATTERN.test(id)), [runIds]);
  const entries = useMemo(() => Object.fromEntries(validRunIds.map((id) => [id, { status: 'open', test_run_id: id }])), [validRunIds]);
  const live = useFindingPages(config, session, entries, 0, readable && validRunIds.length > 0, LIVE_RUN_FINDINGS_LIMIT);
  const perRun = validRunIds.map((id) => ({ id, envelope: live.pages[id] ?? null }));
  const rows = perRun.flatMap(({ envelope }) => envelope?.items ?? []);
  const unknownTotal = perRun.some(({ envelope }) => envelope && envelope.total === null);
  const total = perRun.reduce((sum, { envelope }) => sum + (envelope?.total ?? envelope?.items.length ?? 0), 0);
  const hidden = Math.max(0, total - rows.length);
  return (
    <Card>
      <CardHeader>
        <CardTitle>Findings from captured runs that are open now</CardTitle>
        <CardDescription>Checked {formatDate(checkedAt)} with an open-status server read per captured run. Use it for remediation follow-up; it does not rewrite the report.</CardDescription>
      </CardHeader>
      <CardContent>
        {!readable ? (
          <p className="muted">Your role cannot read findings, so current status is not shown.</p>
        ) : validRunIds.length === 0 ? (
          <p className="muted">This report records no captured run, so no current finding is linked to it.</p>
        ) : live.state === 'loading' ? (
          <p className="muted" role="status">Reading open findings for {formatNumber(validRunIds.length)} captured {validRunIds.length === 1 ? 'run' : 'runs'}.</p>
        ) : live.state === 'error' ? (
          <p className="form-banner error" role="alert">Current findings unavailable: {live.error}</p>
        ) : rows.length === 0 ? (
          <p className="muted">No open finding comes from the {formatNumber(validRunIds.length)} captured {validRunIds.length === 1 ? 'run' : 'runs'}.</p>
        ) : (
          <>
            <p className="muted small">
              {unknownTotal ? `${formatNumber(rows.length)} open shown; the server did not report a total for every run.` : `${formatNumber(total)} open ${total === 1 ? 'finding' : 'findings'} across the captured runs.`}
              {hidden > 0 ? ` Showing the newest ${formatNumber(LIVE_RUN_FINDINGS_LIMIT)} per run; ${formatNumber(hidden)} more are on Findings.` : ''}
            </p>
            <ul className="report-live-list">
              {rows.map((finding) => (
                <li key={getString(finding, ['id'])}>
                  <DetailEntityLink route="finding-detail" id={getString(finding, ['id'])} label={plainFindingTitle(finding, data.targets, data.checks)} />
                  <span className="muted small"> · {formatSeverityLabel(getString(finding, ['severity'], ''))} · run {getString(finding, ['test_run_id'])}</span>
                </li>
              ))}
            </ul>
          </>
        )}
      </CardContent>
    </Card>
  );
}

export function ReportDetailPage({
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
  const [reportQueryTick, setReportQueryTick] = useState(0);
  useEffect(() => {
    function onHashChange() {
      setReportQueryTick((n) => n + 1);
    }
    window.addEventListener('hashchange', onHashChange);
    return () => window.removeEventListener('hashchange', onHashChange);
  }, []);
  const entityId = useMemo(() => getRouteEntityId(''), [reportQueryTick]);
  const reportFallback = data.reports.find((item) => getString(item, ['id'], '') === entityId) ?? null;
  const reportDetail = useEntityDetail(
    Boolean(entityId),
    config,
    session,
    `/v1/reports/${encodeURIComponent(entityId)}`,
    reportFallback
  );
  const report = reportDetail.detail;
  const exporter = useReportExport(config, session, onRefresh);
  const [liveCheckedAt] = useState(() => new Date().toISOString());

  if (!entityId) {
    return (
      <div className="content">
        <DetailPageIntro route="report-detail" eyebrow="Report" />
        <EmptyState
          icon={FileText}
          title="No report selected."
          body="This address does not name a report. Open one from the report list."
          actionLabel="Open reports"
          actionHref="#reports"
        />
      </div>
    );
  }

  if (!report && reportDetail.loading) {
    return (
      <div className="content">
        <DetailPageIntro route="report-detail" eyebrow="Report" />
        <DetailLoadingPlaceholder label="Loading report…" variant="layout" />
      </div>
    );
  }

  if (!report) {
    const denied = /forbidden|permission|403/i.test(reportDetail.error);
    return (
      <div className="content">
        <DetailPageIntro route="report-detail" eyebrow="Report" />
        <EmptyState
          icon={denied ? TriangleAlert : FileText}
          title={denied ? 'Report access required.' : reportDetail.error && !/not.?found|404/i.test(reportDetail.error) ? 'Report could not be loaded.' : 'Report not found.'}
          body={denied
            ? 'Your role cannot read reports in this workspace.'
            : reportDetail.error && !/not.?found|404/i.test(reportDetail.error)
              ? `${reportDetail.error} No other report is shown in its place.`
              : `No report with ID ${entityId} is visible in this workspace.`}
          actionLabel="Open reports"
          actionHref="#reports"
        />
      </div>
    );
  }

  const kind = getString(report, ['kind'], '');
  const summary = getNestedItem(report, ['summary']);
  const frozen = summary?.snapshot_frozen === true;
  const asOf = getString(summary ?? {}, ['as_of'], '') || getString(summary ?? {}, ['generated_at'], '');
  const readinessScore = getNestedNumber(report, ['summary', 'readiness_score'], NaN);
  const hasReadinessScore = Number.isFinite(readinessScore);
  const readinessStatus = getString(summary ?? {}, ['readiness_score_status'], '');
  const readinessReason = getString(summary ?? {}, ['readiness_score_reason'], '');
  const openFindings = getNestedNumber(report, ['summary', 'findings_snapshot', 'open_total'], getNestedNumber(report, ['summary', 'open_findings'], NaN));
  const hasOpenFindings = Number.isFinite(openFindings);
  const readinessFactors = getNestedArray(report, ['summary', 'readiness_factors']);
  const compliance = getNestedItem(report, ['summary', 'compliance']);
  const frameworks = Array.isArray(compliance?.frameworks) ? (compliance!.frameworks as unknown[]).map(String) : [];
  const scope = getNestedItem(summary, ['scope']);
  const scopeMode = getString(scope ?? {}, ['mode'], '');
  const periodBounds = getNestedItem(scope, ['period']);
  const declaredMembers = getNestedItem(scope, ['declared_members']);
  const groupRefs = getNestedArray(scope, ['group_refs']);
  const scopeTargetIds = Array.isArray(scope?.target_ids) ? (scope!.target_ids as unknown[]).map(String) : [];
  const runCapture = getNestedItem(summary, ['run_capture']);
  const findingsSnapshot = getNestedItem(summary, ['findings_snapshot']);
  const snapshotFindings = getNestedArray(findingsSnapshot, ['items']);
  const evidenceSummaries = getNestedItem(summary, ['evidence_summaries']);
  const evidenceItems = getNestedArray(evidenceSummaries, ['items']);
  const declarationSnapshot = getNestedItem(summary, ['declaration_snapshot']);
  const runsSnapshot = getNestedArray(summary, ['runs_snapshot']);
  const explicitRunIds = Array.isArray(report.run_ids)
    ? (report.run_ids as unknown[]).map(String).filter(Boolean)
    : Array.isArray(summary?.run_ids) ? (summary!.run_ids as unknown[]).map(String).filter(Boolean) : [];
  const summaryRuns = getNestedArray(report, ['summary', 'recent_runs']);
  const capturedRunIds = explicitRunIds.length ? explicitRunIds : summaryRuns.map((run) => getString(run, ['id'], '')).filter(Boolean);
  const capturedRows: DataItem[] = capturedRunIds.map((runId) => {
    const snapshotRow = runsSnapshot.find((run) => getString(run, ['id'], '') === runId) ?? null;
    const legacyRow = summaryRuns.find((run) => getString(run, ['id'], '') === runId) ?? null;
    return { id: runId, snapshot: snapshotRow ?? legacyRow, frozen: Boolean(snapshotRow) } as DataItem;
  });
  const capturedEvidenceIds = Array.isArray(summary?.evidence_ids) ? (summary!.evidence_ids as unknown[]).map(String).filter(Boolean) : [];
  const reportTitle = detailEntityTitle('report-detail', report, entityId);
  const countText = (item: DataItem | null) => {
    const included = getNestedNumber(item, ['included'], NaN);
    const total = getNestedNumber(item, ['total'], NaN);
    if (!Number.isFinite(included)) return 'Not recorded';
    return Number.isFinite(total) ? `${formatNumber(included)} of ${formatNumber(total)}` : `${formatNumber(included)} (total not recorded)`;
  };
  const scopeText = !scope
    ? 'Not recorded (legacy report)'
    : scopeMode === 'tenant'
      ? 'Whole workspace'
      : [
        groupRefs.length ? `Groups: ${groupRefs.map((group) => getString(group, ['name'], getString(group, ['id'], ''))).join(', ')}` : '',
        scopeTargetIds.length ? `${formatNumber(scopeTargetIds.length)} selected target${scopeTargetIds.length === 1 ? '' : 's'}` : '',
        scopeMode === 'runs' ? 'Explicit runs' : ''
      ].filter(Boolean).join(' · ') || scopeMode.replaceAll('_', ' ');
  const periodText = periodBounds
    ? getString(periodBounds, ['status'], '') === 'bounded'
      ? `${formatDate(getString(periodBounds, ['start'], ''))} to ${formatDate(getString(periodBounds, ['end'], ''))}`
      : getString(periodBounds, ['status'], '') === 'unbounded' ? `All time, until ${formatDate(getString(periodBounds, ['end'], ''))}` : 'Not recorded'
    : reportPeriodDisplay(data, report) === '—' ? 'Not recorded' : reportPeriodDisplay(data, report);
  const readinessNote = hasReadinessScore
    ? null
    : readinessReason === 'published_readiness_formula_is_tenant_wide'
      ? 'Not included: the published readiness formula covers the whole workspace, so this scoped report has no score.'
      : readinessStatus === 'unknown'
        ? `Not included: ${readinessReason ? readinessReason.replaceAll('_', ' ') : 'readiness was unavailable at generation'}.`
        : 'No readiness score was recorded in this snapshot.';
  const factorColumns: TableColumn<DataItem>[] = [
    { key: 'factor', label: 'Factor', render: (factor) => formatStatusLabel(getString(factor, ['label', 'key'], 'Factor')) },
    { key: 'score', label: 'Score', render: (factor) => {
      const score = getNestedNumber(factor, ['score'], NaN);
      return Number.isFinite(score) ? <span className="tabular-nums">{score}</span> : <span className="muted">Not recorded</span>;
    } },
    { key: 'weight', label: 'Weight', render: (factor) => {
      const weight = getNestedNumber(factor, ['weight'], NaN);
      return Number.isFinite(weight) ? <span className="tabular-nums">{weight}</span> : <span className="muted">Not recorded</span>;
    } },
    { key: 'detail', label: 'Recorded basis', render: (factor) => getString(factor, ['detail', 'reason'], 'Not recorded') }
  ];
  const runColumns: TableColumn<DataItem>[] = [
    { key: 'check', label: 'Check', render: (row) => {
      const checkId = getString((row.snapshot as DataItem | null) ?? {}, ['check_id'], '');
      return checkId ? checkDisplayName(data.checks, checkId) : <span className="muted">Not recorded</span>;
    } },
    { key: 'target', label: 'Target', render: (row) => {
      const targetId = getString((row.snapshot as DataItem | null) ?? {}, ['target_id'], '');
      return targetId ? <DetailEntityLink route="target-detail" id={targetId} /> : <span className="muted">Not recorded</span>;
    } },
    { key: 'status', label: 'Status at capture', render: (row) => {
      const status = getString((row.snapshot as DataItem | null) ?? {}, ['status'], '');
      return status ? formatStatusLabel(status) : <span className="muted">Not captured</span>;
    } },
    { key: 'run', label: 'Run ID', render: (row) => <code className="mono-hash">{getString(row, ['id'])}</code> },
    { key: 'evidence', label: 'Evidence', render: (row) => {
      const snap = (row.snapshot as DataItem | null) ?? {};
      return getString(snap, ['target_id'], '') && getString(snap, ['check_id'], '')
        ? <RunEvidenceButton run={{ ...snap, id: getString(row, ['id']) }} />
        : <span className="muted small">Target or check not captured</span>;
    } }
  ];
  const findingColumns: TableColumn<DataItem>[] = [
    { key: 'title', label: 'Finding at generation', render: (item) => <span className="cp-stack"><span>{getString(item, ['title'], 'Untitled finding')}</span><span className="mono muted small">{getString(item, ['id'])}</span></span> },
    { key: 'severity', label: 'Severity', render: (item) => formatSeverityLabel(getString(item, ['severity'], '')) },
    { key: 'status', label: 'Status at generation', render: (item) => formatStatusLabel(getString(item, ['status'], ''), 'Not recorded') },
    { key: 'proof', label: 'Proof', render: (item) => <Button size="sm" variant="ghost" onClick={() => openEvidenceInspector({ entry: 'finding', finding_id: getString(item, ['id']) }, { focusKey: getString(item, ['id']) })}>View evidence</Button> }
  ];
  const formatOptions = reportOptionsFromCapabilities(data.reportCapabilities, 'formats', REPORT_FORMAT_FALLBACK_OPTIONS);

  return (
    <div className="content report-detail-page">
      <CustomerPageStyles />
      <DetailPageHeader
        route="report-detail"
        eyebrow={`${reportKindIsFramework(kind) ? `${reportKindLabel(kind)} mapping` : `${reportKindLabel(kind)} report`}`}
        entityId={entityId}
        title={reportTitle}
        actions={(
          <>
            <AnchorButton size="sm" variant="ghost" href="#reports">All reports</AnchorButton>
            <Button size="sm" variant="secondary" onClick={() => openEvidenceInspector({ entry: 'report', report_id: entityId })}>View snapshot evidence</Button>
            <ReportExportMenu reportId={entityId} title={reportTitle} formats={formatOptions} exporter={exporter} />
          </>
        )}
      />
      <PageContextSummary>
        Snapshot {asOf ? `frozen ${formatDate(asOf)}` : `created ${formatDate(report.created_at)} (snapshot time not recorded)`} · {scopeText}
      </PageContextSummary>
      {!frozen ? (
        <div className="form-banner neutral" role="note">This is a legacy report: its inputs were not frozen at generation. Only the stored run references and summary values are shown; nothing is filled in from current data.</div>
      ) : null}
      <DetailStatusBanners loadError={reportDetail.error} error={exporter.error} message={exporter.message} mode="combined" />
      <ReportExportResult exporter={exporter} />

      <section className="report-snapshot" aria-labelledby="report-snapshot-heading">
        <h2 id="report-snapshot-heading" className="report-section-title">At generation <span className="muted">· fixed snapshot</span></h2>
        <div className="report-snapshot-grid">
          <Card>
            <CardHeader>
              <CardTitle>Scope and period</CardTitle>
              <CardDescription>Exactly what this report covers, as recorded.</CardDescription>
            </CardHeader>
            <CardContent className="kv-list">
              <div><span>Scope</span><strong>{scopeText}</strong></div>
              <div><span>Period</span><strong>{periodText}</strong></div>
              <div><span>Declared targets captured</span><strong>{countText(declaredMembers)}</strong></div>
              <div><span>Runs captured</span><strong>{runCapture ? `${countText(runCapture)}${getString(runCapture, ['limit'], '') ? `, most recent ${getString(runCapture, ['limit'], '')}` : ''}` : `${formatNumber(capturedRunIds.length)} (total not recorded)`}</strong></div>
              <div><span>Findings captured</span><strong>{findingsSnapshot ? countText(findingsSnapshot) : 'Not recorded'}</strong></div>
              <div><span>Open findings at generation</span><strong>{hasOpenFindings ? openFindings : 'Not recorded'}</strong></div>
            </CardContent>
          </Card>
          <Card>
            <CardHeader>
              <CardTitle>Readiness at {asOf ? formatDate(asOf) : 'generation'}</CardTitle>
              <CardDescription>Values recorded in the report. They do not change when current results change.</CardDescription>
            </CardHeader>
            <CardContent className="kv-list report-summary-layout">
              {hasReadinessScore ? <ReadinessGauge score={readinessScore} /> : <p className="cp-note">{readinessNote}</p>}
              <div><span>{reportKindIsFramework(kind) ? 'Framework mapping' : 'Audience'}</span><strong>{compliance ? getString(compliance, ['template_title'], reportKindLabel(kind)) : reportKindLabel(kind)}</strong></div>
              {frameworks.length ? <div><span>Frameworks</span><strong>{frameworks.map((framework) => plainCodeLabel(framework)).join(', ')}</strong></div> : null}
              <div><span>Status</span><StatusBadge value={getString(report, ['status'], '')} tone={reportStatusBadgeTone(getString(report, ['status'], ''))} fallback="Not recorded" /></div>
            </CardContent>
          </Card>
        </div>
        <p className="cp-note">{getString(compliance ?? {}, ['disclaimer'], 'Evidence mapping is not a certification or a statement of compliance.')} Protection profiles are {getNestedString(summary, ['sections', 'protection_profile', 'status'], 'not_included') === 'included' ? 'included' : 'not included in this report'}.</p>
        {readinessFactors.length ? (
          <Card>
            <CardHeader>
              <CardTitle>Score factors in this snapshot</CardTitle>
              <CardDescription>As recorded; not recalculated from current data.</CardDescription>
            </CardHeader>
            <CardContent>
              <DataTable columns={factorColumns} items={readinessFactors} getRowId={(factor) => getString(factor, ['key', 'label'], JSON.stringify(factor))} empty={null} />
            </CardContent>
          </Card>
        ) : null}
        <Card>
          <CardHeader>
            <CardTitle>Runs captured by this report ({formatNumber(capturedRunIds.length)})</CardTitle>
            <CardDescription>Every stored run reference, in recorded order{frozen ? ', with the details frozen at generation' : ''}. Evidence opens beside this page.</CardDescription>
          </CardHeader>
          <CardContent>
            <DataTable
              columns={runColumns}
              items={capturedRows}
              getRowId={(row) => getString(row, ['id'], '')}
              empty={<EmptyState icon={Target} title="No run references recorded." body="This report did not capture any run IDs." />}
            />
          </CardContent>
        </Card>
        {findingsSnapshot ? (
          <Card>
            <CardHeader>
              <CardTitle>Findings captured ({countText(findingsSnapshot)})</CardTitle>
              <CardDescription>Lifecycle as it was at generation. Current status is shown separately below.</CardDescription>
            </CardHeader>
            <CardContent>
              <DataTable
                columns={findingColumns}
                items={snapshotFindings}
                getRowId={(item) => getString(item, ['id'], '')}
                empty={<EmptyState icon={TriangleAlert} title="No findings in scope at generation." body="No finding matched this report's scope and period." />}
              />
            </CardContent>
          </Card>
        ) : null}
        <Card>
          <CardHeader>
            <CardTitle>Evidence references ({formatNumber(capturedEvidenceIds.length)})</CardTitle>
            <CardDescription>Every evidence ID the snapshot references. Opening one shows its recorded integrity; a reference is not verification.</CardDescription>
          </CardHeader>
          <CardContent>
            {capturedEvidenceIds.length === 0 ? <p className="muted">{summary ? 'No evidence references were captured.' : 'Not recorded (legacy report).'}</p> : (
              <ul className="report-live-list">
                {capturedEvidenceIds.map((evidenceId) => {
                  const known = evidenceItems.find((item) => getString(item, ['id'], '') === evidenceId);
                  return (
                    <li key={evidenceId} className="row-actions">
                      <code className="mono-hash">{evidenceId}</code>
                      {known ? <span className="muted small">{getString(known, ['label'], '')}</span> : null}
                      <Button size="sm" variant="ghost" onClick={() => openEvidenceInspector({ entry: 'artifact', evidence_id: evidenceId }, { focusKey: evidenceId })}>View evidence</Button>
                    </li>
                  );
                })}
              </ul>
            )}
          </CardContent>
        </Card>
        {declarationSnapshot ? (
          <p className="muted small">Declarations: {getString(declarationSnapshot, ['status'], 'not recorded').replaceAll('_', ' ')}{getNestedArray(declarationSnapshot, ['items']).length ? ` · ${formatNumber(getNestedArray(declarationSnapshot, ['items']).length)} target declarations frozen` : ''}.</p>
        ) : null}
      </section>

      <section className="report-live" aria-labelledby="report-live-heading">
        <h2 id="report-live-heading" className="report-section-title">Current status <span className="muted">· live, not part of the report</span></h2>
        <ReportLiveOpenFindings data={data} config={config} session={session} runIds={capturedRunIds} checkedAt={liveCheckedAt} />
      </section>
    </div>
  );
}
