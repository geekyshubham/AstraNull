import { useCallback, useEffect, useMemo, useRef, useState, type FormEvent, type HTMLAttributes, type KeyboardEvent, type ReactNode } from 'react';
import { Activity, Bot, ChevronRight, CircleDashed, ClipboardList, FileCheck2, FileText, Info, Network, ShieldCheck, Siren, Target, TriangleAlert, UserCog, Users } from 'lucide-react';
import { FindingExplanationPanel } from '../components/findings/finding-explanation-panel';
import { Badge, type BadgeProps } from '../components/ui/badge';
import { CheckClassSummary } from '../components/checks/check-class-chips';
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
import { buildEvidenceCustodyManifest, CUSTODY_CONTENT_CANONICALIZATION, sha256HexBytes } from '../lib/custody';
import type { DataItem, PortalConfig, PortalData, RouteId, Session } from '../lib/types';
import { formatAuditAction, formatDate, formatDurationSeconds, formatNumber, formatResourceTypeLabel, formatSeverityLabel, formatTimestamp, pluralize, scoreTone, sensitiveResourceLabel, triggerJsonDownload, triggerTextDownload } from '../lib/utils';
import { hasEvidenceBackedVerdict } from '../lib/run-verdict';
import { CapabilityProbeResultsPanel } from '../components/runs/capability-probe-panel';
import { VerdictReplay } from '../components/runs/verdict-replay';
import { ConfirmModal, formatMutationSuccessMessage, useConfirmModal } from '../lib/crud-ui';
import { RunTimelineViz, TrafficPathPanel, TruthTablePanel, VerdictExplanationPanel } from '../components/runs/run-proof-panels';
import { NotTestedBadge, NotTestedNote } from '../components/runs/not-tested-note';
import { requiredInputMissing } from '../lib/missing-input.mjs';
import {
  isSignedProbeEvidenceEvent,
} from '../lib/verdict-explanation';
import { findingSlaDueAt, findingStatus, isFindingSlaBreach, resolveFindingRetestAction } from '../lib/findings-helpers';
import {
  authorizationArtifactPurpose,
  authorizationArtifactTitle,
  authorizationArtifactTypesForRequest,
  authorizationLetterValidWindow,
  bestArtifactForType,
  killSwitchActiveForTenant,
  orderedArtifactsForType,
  buildLifecycleTimeline,
  buildMetadataArtifactUploadBody,
  defaultScheduleWindow,
  explainArtifactReviewStatus,
  fromDatetimeLocalValue,
  governedLimitDisplay,
  governedScenarioLabel,
  packRequirementForType,
  requestDomainDisplay,
  scheduledWindowState,
  scheduleWindowErrors,
  summarizeAuthorizationPackProgress,
  toDatetimeLocalValue
} from '../lib/high-scale';
import { routeTabs } from '../lib/prototype-manifest';
import { ReadinessGauge } from '../components/charts/readiness-gauge';
import { artifactReviewTone, findingStatusTone, highScaleStateTone, reportStatusTone, runStatusTone as runStatusBadgeTone, statusKey, subscriptionStatusTone, tenantLifecycleTone, verdictTone } from '../lib/status-tone';
import { severityTone } from '../lib/severity-tone';
import {
  CustomerPageStyles,
  ENTITLEMENT_FEATURE_LABELS,
  KpiCell,
  MetricCard,
  PageContextSummary,
  PageTitle,
  RecordedKvRow,
  REPORT_FORMAT_FALLBACK_OPTIONS,
  ReportExportMenu,
  ReportExportResult,
  reportKindIsFramework,
  reportKindLabel,
  reportOptionsFromCapabilities,
  useReportExport
} from './page-components';
import { effectivePolicyTargetKind, isPolicyTargetCompatible } from '../lib/policy-targets';
import { TargetDetailView } from './target-detail-view';
import { FindingDetailView as FindingDetailViewRevamp } from './finding-detail-view';
import './detail-pages.css';
// @ts-ignore Plain ESM keeps executive labels directly testable with node:test.
import { plainCheckName, plainCodeLabel, plainExpectedVerdictLabel, plainFindingTitle, plainInlineText, plainVerdictLabel, plainVerdictShortLabel } from '../lib/plain-language.mjs';
import { DetailBackLink, type DetailListLink } from '../components/layout/detail-back-link';
import { useEntityDocumentTitle } from '../components/layout/app-shell';
import { diffReports, eligibleBaselines, reportAsOf } from '../lib/report-diff';


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

function staffEntitlementLabel(feature: string) {
  return (ENTITLEMENT_FEATURE_LABELS as Record<string, string>)[feature] ?? formatStatusLabel(feature);
}

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

function TimelinePanel({ items }: { items: Array<{ label: string; at?: unknown; by?: string }> }) {
  if (items.length === 0) {
    return <EmptyState icon={Activity} title="No timeline milestones recorded." body="Milestones appear here as this record moves through its lifecycle." />;
  }
  return (
    <div className="timeline-list">
      {items.map((item, index) => (
        <div key={`${item.label}-${index}`}>
          <span aria-hidden="true" />
          <div>
            <strong>{item.label}</strong>
            <p>{formatDate(item.at)}{'by' in item ? ` · ${item.by || 'system'}` : ''}</p>
          </div>
        </div>
      ))}
    </div>
  );
}

type StatusBadgeTone = NonNullable<BadgeProps['tone']>;

const DETAIL_SKELETON_KV_ROWS = 6;
const DETAIL_SKELETON_TAB_COUNT = 4;


function formatStatusLabel(value: string, fallback = '—') {
  const trimmed = value.trim();
  if (!trimmed) return fallback;
  const label = trimmed.replace(/_/g, ' ');
  return label.charAt(0).toUpperCase() + label.slice(1);
}






function discoveryEntityStateBadgeTone(state: string): StatusBadgeTone {
  const key = statusKey(state);
  if (['approved', 'active', 'entity', 'imported'].includes(key)) return 'success';
  if (key === 'rejected') return 'danger';
  return 'warn';
}

function signupRequestStateTone(state: string): StatusBadgeTone {
  const key = statusKey(state);
  if (['approved', 'provisioned', 'active'].includes(key)) return 'success';
  if (['rejected', 'denied', 'cancelled', 'canceled'].includes(key)) return 'danger';
  if (['under_review', 'reviewing', 'in_review'].includes(key)) return 'warn';
  return 'muted';
}

function supplyChainExposureLabel(type: string) {
  const match = SUPPLY_CHAIN_EXPOSURE_TYPES.find((entry) => entry.id === type);
  return match?.label ?? formatStatusLabel(type);
}




function cveStageBadgeTone(stage: string): StatusBadgeTone {
  const key = statusKey(stage);
  if (['validated', 'mitigated', 'closed'].includes(key)) return 'success';
  if (['triage', 'ingest'].includes(key)) return 'muted';
  if (['exposed', 'active'].includes(key)) return 'danger';
  return 'warn';
}

function supplyChainStateBadgeTone(state: string): StatusBadgeTone {
  const key = statusKey(state);
  if (key === 'confirmed') return 'danger';
  if (key === 'suspected') return 'warn';
  if (key === 'mitigated' || key === 'resolved') return 'success';
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

function DetailPageIntro({ route, context }: { route: RouteId; context?: string }) {
  const item = ROUTE_BY_ID.get(route);
  const description = item?.description?.trim();
  return (
    <>
      <PageTitle context={context}>{item?.label ?? 'Detail'}</PageTitle>
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


const DETAIL_LINK_ROUTES: RouteId[] = [
  'run-detail',
  'check-detail',
  'policy-detail',
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
  if (route === 'report-detail') return getString(entity, ['title'], entityId);
  if (route === 'tenant-detail') {
    const tenant = getNestedItem(entity, ['tenant']) ?? entity;
    return getString(tenant, ['name'], entityId);
  }
  return getString(entity, ['name', 'hostname', 'canonical_url', 'cve_id', 'organization_name', 'id'], entityId);
}


// Prefixed record IDs plus dotted catalog check IDs (e.g. origin.leak_scan.safe) stay visible as
// secondary engineer-facing text under the plain-English title.
const VISIBLE_DETAIL_ID_RE = /^(?:(?:tgt|tg|run|fnd|evt|agt|env|rpt|scan|usr|ten|wof|id|job|evd|btok|dns)_|[a-z0-9]+(?:_[a-z0-9]+)*(?:\.[a-z0-9]+(?:_[a-z0-9]+)*){1,4}$)/;

function DetailEntityHeading({
  route,
  entityId,
  title,
  context,
  backLink
}: {
  route: RouteId;
  entityId: string;
  title: string;
  context?: string;
  backLink?: DetailListLink;
}) {
  useEntityDocumentTitle(title || undefined);
  return (
    <>
      <DetailBackLink route={route} link={backLink} />
      <PageTitle context={context}>{title}</PageTitle>
      {title !== entityId && VISIBLE_DETAIL_ID_RE.test(entityId) ? <p className="muted"><code>{entityId}</code></p> : null}
    </>
  );
}

function DetailPageHeader({
  route,
  context,
  entityId,
  title,
  description,
  actions,
  backLink
}: {
  route: RouteId;
  context?: string;
  entityId: string;
  title: string;
  description?: ReactNode;
  actions?: ReactNode;
  backLink?: DetailListLink;
}) {
  return (
    <div className="page-head">
      <div>
        <DetailEntityHeading route={route} entityId={entityId} title={title} context={context} backLink={backLink} />
        {description ? <p>{description}</p> : null}
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
    <a className="detail-entity-link" href={buildDetailHref(route, id)}>
      {resolved}
    </a>
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
    <div className="kv-mono-field">
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
  const [reloadTick, setReloadTick] = useState(0);
  const reloadWaitersRef = useRef<Array<() => void>>([]);
  const reload = useCallback(() => new Promise<void>((resolve) => {
    reloadWaitersRef.current.push(resolve);
    setReloadTick((n) => n + 1);
  }), []);
  // See useEntityDetail: `fallback` has a fresh identity every render, so it must not
  // gate the fetch effect — read it through a ref and omit it from the deps below.
  const fallbackRef = useRef(fallback);
  fallbackRef.current = fallback;
  const loadedKeyRef = useRef('');

  useEffect(() => {
    const settleWaiters = () => {
      const waiters = reloadWaitersRef.current;
      reloadWaitersRef.current = [];
      for (const resolve of waiters) resolve();
    };
    if (!enabled || !entityId) {
      setDetail(fallbackRef.current);
      setLoading(false);
      settleWaiters();
      return;
    }
    let cancelled = false;
    const key = `${listPath}|${entityId}|${tenantId ?? ''}|${staffSoc}`;
    const isReload = loadedKeyRef.current === key;
    if (!isReload) setLoading(true);
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
        loadedKeyRef.current = key;
        if (match) {
          setDetail(match);
        } else if (!isReload) {
          setDetail(fallbackRef.current);
          if (!fallbackRef.current) setError('Entity not found in your workspace lists.');
        } else {
          setError('This request is no longer in your workspace lists.');
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
  }, [config, session, listPath, enabled, entityId, staffSoc, tenantId, reloadTick]);

  return { detail, error, loading, reload };
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
  const runPolicyId = getString(entity, ['policy_id', 'test_policy_id'], '');
  const runPolicy = runPolicyId ? (data.testPolicies ?? []).find((item) => getString(item, ['id', 'policy_id'], '') === runPolicyId) ?? null : null;
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
  const runTargetId = getString(entity, ['target_id'], '');
  const runTargetMatch = runTargetId ? data.targets.find((item) => getString(item, ['id'], '') === runTargetId) : undefined;
  const runTargetValue = getString(entity, ['target_value'], '') || getString(runTargetMatch ?? {}, ['value', 'hostname'], '');
  const runCheckId = getString(entity, ['check_id'], '');
  const runTargetHref = runTargetId
    ? `${buildDetailHref('target-detail', runTargetId)}${runCheckId ? `&tab=validate&check=${encodeURIComponent(runCheckId)}` : ''}`
    : '';
  const runCheckRecord = runCheckId ? data.checks.find((item) => getString(item, ['check_id', 'id'], '') === runCheckId) : undefined;
  const runFamily = getString(entity, ['vector_family'], '') || getString(runCheckRecord ?? {}, ['vector_family', 'family'], '');
  const explicitRunValidationMode = getString(entity, ['validation_mode'], 'external_only');
  const verdictValue = hasEvidenceBackedVerdict(entity, data.evidence)
    ? getNestedString(entity, ['verdict', 'verdict'], runVerdictValue(entity))
    : '';
  const runNotTested = requiredInputMissing(entity);
  const verdictDisplay = runNotTested ? runNotTested.label : verdictValue ? plainVerdictShortLabel(verdictValue) : 'No result yet';
  const verdictSub = runNotTested ? 'Nothing was sent · missing input' : verdictValue ? `${plainVerdictLabel(verdictValue)} · External-only confidence` : 'External-only confidence';
  const primaryFinding = relatedFindings[0] ?? null;
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
        entityId={entityId}
        title={runTitle}
        backLink={runTargetId ? { label: runTargetValue || 'target', href: runTargetHref } : undefined}
        actions={(
          <>
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
        {explicitRunValidationMode ? formatStatusLabel(explicitRunValidationMode) : 'Validation mode not recorded'}
      </PageContextSummary>
      {loading ? <DetailLoadingPlaceholder label="Loading run detail…" /> : null}
      <DetailStatusBanners loadError={loadError} error={error} message={message} successTone="neutral" />
      {runEventEvidenceUnavailable ? (
        <div className="form-banner error" role="alert">
          <strong>{runEventState.error || 'Run event evidence unavailable.'}</strong>{' '}
          Run events could not be loaded. Try again shortly.
        </div>
      ) : null}
      {!loading ? (
        <>
          <div className="metric-grid four run-detail-metrics">
            <MetricCard
              label="Target"
              value={runTargetId
                ? <a className="detail-entity-link" href={runTargetHref}>{runTargetValue || <code>{runTargetId}</code>}</a>
                : 'Not recorded'}
              sub="Declared endpoint under test"
              icon={Target}
              tone="muted"
            />
            <MetricCard label="Check" value={checkDisplayName(data.checks, runCheckId)} sub={runFamily ? plainCodeLabel(runFamily, 'Family not recorded') : 'Family not recorded'} icon={FileCheck2} tone="muted" />
            <MetricCard label="Verdict" value={verdictDisplay} sub={verdictSub} icon={ShieldCheck} tone={verdictValue && !runNotTested ? verdictTone(verdictValue) : 'muted'} />
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
                      <div className="run-proof-panels">
                        <TrafficPathPanel detail={entity} events={trustedEvidenceEvents} />
                      </div>
                    )}
                    <div className="kv-list">
                      <div><span>Stored verdict</span>{runNotTested ? <Badge tone="muted">{runNotTested.label}</Badge> : verdictValue ? <VerdictBadge value={verdictValue} tone={verdictTone(verdictValue)} /> : <strong>No result yet</strong>}</div>
                      <div><span>Trusted events</span><strong>{runEventEvidenceLoading || runEventEvidenceUnavailable ? '—' : trustedEvidenceEvents.length}</strong></div>
                    </div>
                    {runNotTested ? <NotTestedNote info={runNotTested} targetId={runTargetId} showLabel={false} /> : null}
                    {verdictValue ? <VerdictReplay config={config} session={session} runId={entityId} /> : null}
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
                    <div><span>Check</span>{runCheckId ? <DetailEntityLink route="check-detail" id={runCheckId} label={checkDisplayName(data.checks, runCheckId)} /> : <strong>Not recorded</strong>}</div>
                    <div><span>Target</span>{runTargetId ? <DetailEntityLink route="target-detail" id={runTargetId} label={runTargetValue || undefined} /> : <strong>Not recorded</strong>}</div>
                    <div><span>Schedule</span>{runPolicyId ? <DetailEntityLink route="policy-detail" id={runPolicyId} label={runPolicy ? scheduleDisplayName(runPolicy, data.checks) : 'Open schedule'} /> : <strong>Not started by a schedule</strong>}</div>
                    <div><span>Validation mode</span><strong>{explicitRunValidationMode ? formatStatusLabel(explicitRunValidationMode) : 'Not recorded'}</strong></div>
                    <div><span>Created</span><strong>{formatDate(entity.created_at)}</strong></div>
                    <div><span>Started</span><strong>{formatDate(entity.started_at)}</strong></div>
                    <div><span>Completed</span><strong>{formatDate(getNestedString(entity, ['verdict', 'finalized_at'], '') || entity.completed_at)}</strong></div>
                    <div><span>Initiated by</span><strong>{getString(entity, ['initiated_by', 'created_by'], 'Not recorded')}</strong></div>
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
                    <div className="run-proof-panels">
                      <VerdictExplanationPanel detail={entity} events={trustedEvidenceEvents} />
                      <TruthTablePanel detail={entity} />
                    </div>
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
                  Ordered run lifecycle and trusted event provenance{runPolicyId ? <span title={runPolicyId}> · started by a schedule</span> : null}.
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
                    <CapabilityProbeResultsPanel events={probeEvents} verdictPortResults={verdict?.port_results ?? (verdict?.placement_confidence as DataItem | undefined)?.port_results} />
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
                    <EmptyState
                      icon={FileCheck2}
                      title="No linked evidence records."
                      body="No evidence artifact in the loaded vault data identifies this run."
                      actionLabel={runTargetId ? 'Open target' : undefined}
                      actionHref={runTargetId ? buildDetailHref('target-detail', runTargetId) : undefined}
                    />
                  ) : (
                    <div className="kv-list">
                      {relatedEvidence.map((item) => {
                        const evidenceId = getString(item, ['id', 'evidence_id'], '');
                        const evidenceLabel = humanizeSignalType(getString(item, ['label', 'kind', 'signal_type'], ''));
                        const digest = getString(item, ['content_sha256', 'custody_digest'], '');
                        const shortDigest = digest.length > 16 ? `${digest.slice(0, 12)}…` : digest;
                        return (
                          <div key={evidenceId}>
                            <span>{evidenceLabel}</span>
                            <strong>
                              <DetailEntityLink route="evidence-detail" id={evidenceId} label={evidenceLabel} />
                              {digest ? <span className="muted small"> · <code className="mono-hash" title={digest}>{shortDigest}</code></span> : null}
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
                  <CardDescription>Findings raised from this run.</CardDescription>
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
                              {' · '}<StatusBadge value={getString(finding, ['severity'], 'unknown')} tone={severityTone(getString(finding, ['severity'], 'unknown'))} fallback="unknown" />
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
                  <p className="muted">Run events could not be loaded. Try again shortly.</p>
                ) : (
                  <DataTable
                    columns={rawEventColumns}
                    items={runEvents}
                    empty={<EmptyState icon={ClipboardList} title="No run events recorded." body="No events were recorded for this run." />}
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
        description={<p>Run {entityId} stops collecting and records no verdict.</p>}
        confirmLabel="Cancel run"
        dismissLabel="Keep run"
        busy={busy === `cancel-${entityId}`}
        onCancel={() => setConfirmCancelOpen(false)}
        onConfirm={() => void confirmCancelRun()}
      />
      <ConfirmModal
        open={canManageRun && confirmFinalizeOpen}
        title="Force finalize this run now?"
        description={<p>Publishes a verdict from the signed probe evidence already recorded for this run. The run must have probe evidence and a closed observation window. The published verdict cannot be changed.</p>}
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
  const { confirm, confirmWithReason } = useConfirmModal();
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
  const lifecycleRecorded = Boolean(getString(account, ['lifecycle_state'], ''));
  const lifecycleState = lifecycleRecorded ? getString(account, ['lifecycle_state'], '') : 'unrecorded';
  const lifecycleLabel = lifecycleRecorded ? formatStatusLabel(lifecycleState) : 'Not recorded';
  const tenantTitle = getString(tenant, ['name'], entityId);
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

  async function patchLifecycle(nextState: 'active' | 'suspended') {
    const suspending = nextState === 'suspended';
    const userCount = users.length;
    const reason = await confirmWithReason({
      title: suspending ? `Suspend ${tenantTitle}?` : lifecycleRecorded ? `Reactivate ${tenantTitle}?` : `Record ${tenantTitle} as active?`,
      description: suspending
        ? `${formatNumber(userCount)} ${pluralize(userCount, 'user')} will lose access immediately until staff reactivate the tenant.`
        : lifecycleRecorded
          ? `${formatNumber(userCount)} ${pluralize(userCount, 'user')} regain access to this tenant immediately.`
          : 'No lifecycle state is recorded for this tenant. This records it as active; user access does not change.',
      confirmLabel: suspending ? 'Suspend tenant' : lifecycleRecorded ? 'Reactivate tenant' : 'Record as active',
      confirmTone: suspending ? 'danger' : 'default',
      requireTypedId: suspending ? entityId : undefined,
      reason: { label: 'Reason (recorded in the staff audit log)', required: true }
    });
    if (reason === null) return;
    await runStaffAction(`lifecycle-${entityId}-${nextState}`, () => requestJson(config, session, `/internal/admin/tenants/${encodeURIComponent(entityId)}`, {
      method: 'PATCH',
      body: { lifecycle_state: nextState, reason }
    }), suspending ? `${tenantTitle} suspended.` : `${tenantTitle} recorded as active.`);
  }

  async function patchSupportOwner(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const owner = String(form.get('support_owner') ?? '').trim();
    const reason = String(form.get('reason') ?? '').trim();
    if (!owner || !reason) return;
    await runStaffAction(`support-owner-${entityId}`, () => requestJson(config, session, `/internal/admin/tenants/${encodeURIComponent(entityId)}`, {
      method: 'PATCH',
      body: { support_owner: owner, reason }
    }), `Support owner for ${tenantTitle} updated.`);
  }

  async function grantEntitlement(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const feature = String(form.get('feature') ?? '').trim();
    const enabled = String(form.get('enabled') ?? 'true') === 'true';
    const reason = String(form.get('reason') ?? '').trim();
    if (!feature || !reason) return;
    const featureLabel = staffEntitlementLabel(feature);
    if (!await confirm({
      title: `${enabled ? 'Grant' : 'Revoke'} ${featureLabel} for ${tenantTitle}?`,
      description: `${enabled ? 'Grant' : 'Revoke'} ${featureLabel} for ${tenantTitle}? This changes product access immediately. Reason: ${reason}`,
      confirmLabel: `${enabled ? 'Grant' : 'Revoke'} entitlement`,
      confirmTone: enabled ? 'default' : 'danger'
    })) return;
    await runStaffAction(`entitlement-${entityId}-${feature}`, () => requestJson(config, session, `/internal/admin/tenants/${encodeURIComponent(entityId)}/entitlements`, {
      method: 'POST',
      body: { feature, enabled, reason }
    }), `${featureLabel} ${enabled ? 'granted to' : 'revoked from'} ${tenantTitle}.`);
  }

  async function resendInvite(userId: string) {
    await runStaffAction(`resend-${entityId}-${userId}`, () => requestJson(config, session, `/internal/admin/tenants/${encodeURIComponent(entityId)}/users/${encodeURIComponent(userId)}/resend-invite`, {
      method: 'POST',
      body: {}
    }), 'Invite resend recorded.');
  }

  async function disableUser(user: DataItem) {
    const userId = getString(user, ['id'], '');
    if (!userId) return;
    const email = getString(user, ['email'], userId);
    const reason = await confirmWithReason({
      title: `Disable ${email} in ${tenantTitle}?`,
      description: 'They lose access to this tenant immediately until staff re-enable them.',
      confirmLabel: 'Disable user',
      confirmTone: 'danger',
      reason: { label: 'Reason (recorded in the staff audit log)', required: true }
    });
    if (reason === null) return;
    await runStaffAction(`disable-${entityId}-${userId}`, () => requestJson(config, session, `/internal/admin/tenants/${encodeURIComponent(entityId)}/users/${encodeURIComponent(userId)}/disable`, {
      method: 'POST',
      body: { reason }
    }), `${email} disabled.`);
  }

  const userColumns: TableColumn<DataItem>[] = [
    { key: 'email', label: 'Email', render: (item) => getString(item, ['email']) },
    { key: 'role', label: 'Role', render: (item) => <Badge tone="muted" title={getString(item, ['role'], '')}>{plainCodeLabel(getString(item, ['role'], ''), 'Not recorded')}</Badge> },
    { key: 'status', label: 'Status', render: (item) => <Badge tone={getString(item, ['status']) === 'active' ? 'success' : 'warn'} title={getString(item, ['status'], '')}>{plainCodeLabel(getString(item, ['status'], ''), 'Not recorded')}</Badge> },
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
            <Button size="sm" variant="danger" disabled={busy !== ''} onClick={() => void disableUser(item)}>Disable</Button>
          </div>
        );
      }
    }
  ];

  const approvalColumns: TableColumn<DataItem>[] = [
    { key: 'kind', label: 'Kind', render: (item) => <span title={getString(item, ['kind'], '')}>{plainCodeLabel(getString(item, ['kind'], ''), 'Not recorded')}</span> },
    { key: 'state', label: 'State', render: (item) => <Badge tone="warn" title={getString(item, ['state'], '')}>{plainCodeLabel(getString(item, ['state'], ''), 'Not recorded')}</Badge> },
    { key: 'created', label: 'Created', render: (item) => formatDate(item.created_at) }
  ];

  const auditColumns: TableColumn<DataItem>[] = [
    { key: 'action', label: 'Action', render: (item) => <span title={getString(item, ['action'], '')}>{formatAuditAction(getString(item, ['action'], ''), 'Unknown action', item.metadata)}</span> },
    { key: 'actor', label: 'Actor', render: (item) => getString(item, ['actor_user_id', 'staff_id'], '—') },
    { key: 'resource', label: 'Resource', render: (item) => {
      const type = getString(item, ['resource_type'], '');
      return sensitiveResourceLabel(type) ?? `${formatResourceTypeLabel(type)} · ${getString(item, ['resource_id'], 'ID not recorded')}`;
    } },
    { key: 'time', label: 'Time', render: (item) => formatDate(item.timestamp ?? item.created_at) }
  ];

  return (
    <div className="content">
      <DetailPageHeader
        route="tenant-detail"
        context="Staff-only surface"
        entityId={entityId}
        title={tenantTitle}
        actions={(
          <>
            {lifecycleState === 'suspended' ? (
              <Button size="sm" variant="secondary" disabled={busy !== ''} onClick={() => void patchLifecycle('active')}>Activate</Button>
            ) : null}
            {!lifecycleRecorded ? (
              <Button size="sm" variant="secondary" disabled={busy !== ''} onClick={() => void patchLifecycle('active')}>Record as active</Button>
            ) : null}
            {lifecycleState !== 'suspended' ? (
              <Button size="sm" variant="danger" disabled={busy !== ''} onClick={() => void patchLifecycle('suspended')}>Suspend</Button>
            ) : null}
          </>
        )}
      />
      {loading ? <DetailLoadingPlaceholder label="Loading tenant detail…" /> : null}
      <DetailStatusBanners loadError={loadError} error={error} message={message} mode="combined" />
      {!loading ? (
        <>
          <div className="kpi-row" role="group" aria-label="Tenant summary">
            <KpiCell label="Lifecycle" value={lifecycleLabel} delta={lifecycleRecorded ? 'Staff account state' : 'No account record'} tone={!lifecycleRecorded ? 'muted' : lifecycleState === 'active' ? 'success' : 'warn'} />
            <KpiCell label="Plan" value={getString(subscription, ['plan_id'], '—')} valueClassName={getString(subscription, ['plan_id'], '') ? 'mono' : undefined} delta={formatStatusLabel(getString(subscription, ['status'], 'Not recorded'))} tone="muted" />
            <KpiCell label="Users" value={formatNumber(users.length)} delta="Tenant-scoped identities" tone="muted" />
            <KpiCell label="Recent audit" value={formatNumber(recentAudit.length)} delta={`${pluralize(recentAudit.length, 'event')} in this response`} tone="muted" />
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
                    <CardDescription>Tenant identity, residency, and support ownership recorded by staff administration.</CardDescription>
                  </CardHeader>
                  <CardContent className="kv-list">
                    <div><span>Name</span><strong>{getString(tenant, ['name'])}</strong></div>
                    <DetailKvMonoField label="Tenant ID" value={entityId} />
                    <RecordedKvRow label="Region" value={getString(account, ['region'], '')} />
                    <RecordedKvRow label="Support owner" value={getString(account, ['support_owner'], '')} missing="Unassigned" mono />
                    <RecordedKvRow label="Created" value={tenant?.created_at ? formatDate(tenant.created_at) : ''} />
                    <RecordedKvRow label="Updated" value={tenant?.updated_at ?? account?.updated_at ? formatDate(tenant?.updated_at ?? account?.updated_at) : ''} />
                  </CardContent>
                </Card>
                <Card>
                  <CardHeader>
                    <CardTitle>Provisioning relationship</CardTitle>
                    <CardDescription>Signup request and internal approval records explicitly scoped to this tenant.</CardDescription>
                  </CardHeader>
                  <CardContent className="stack-tight">
                    <div className="kv-list">
                      {signupRequest ? (
                        <>
                          <DetailKvMonoField label="Signup request" value={getString(signupRequest, ['id'], 'Not returned')} />
                          <div><span>Signup state</span><StatusBadge value={getString(signupRequest, ['state'], 'recorded')} tone={signupRequestStateTone(getString(signupRequest, ['state']))} fallback="recorded" /></div>
                        </>
                      ) : (
                        <RecordedKvRow label="Signup request" value="" missing="None linked" />
                      )}
                      {relatedApprovals.length === 0 ? (
                        <RecordedKvRow
                          label="Approval requests"
                          value=""
                          missing={!canReadDataset(session, 'internalApprovalRequests') ? 'Not visible to your role' : data.loadErrors.internalApprovalRequests ? 'Could not be loaded' : 'None recorded'}
                        />
                      ) : null}
                    </div>
                    {relatedApprovals.length > 0 ? (
                      <DataTable
                        columns={approvalColumns}
                        items={relatedApprovals}
                        empty={<EmptyState icon={ShieldCheck} title="No tenant approval requests." body="No loaded internal approval record identifies this tenant." />}
                      />
                    ) : null}
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
                    <label className="full"><span>Support owner</span><input name="support_owner" defaultValue={getString(account, ['support_owner'], '')} placeholder="e.g. owner@customer.example" required /></label>
                    <label className="full"><span>Reason (recorded in the staff audit log)</span><input name="reason" placeholder="Account handover to the regional support team" required /></label>
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
                    <div><span>Plan</span><strong>{getString(subscription, ['plan_id'], 'Not recorded')}</strong></div>
                    <div><span>Status</span><StatusBadge value={getString(subscription, ['status'], 'Not recorded')} tone={subscriptionStatusTone(getString(subscription, ['status'], ''))} fallback="Not recorded" /></div>
                    <div><span>MRR</span><strong>{mrrValue || 'Not returned'}</strong></div>
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
                        <span>{staffEntitlementLabel(feature)}</span>
                        <StatusBadge
                          value={effectiveEntitlements[feature] === true ? 'enabled' : 'disabled'}
                          tone={effectiveEntitlements[feature] === true ? 'success' : 'muted'}
                        />
                      </div>
                    )) : <p className="muted">No entitlement decisions are recorded for this subscription.</p>}
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
                        label: staffEntitlementLabel(feature)
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
                <DataTable columns={auditColumns} items={recentAudit} empty={<EmptyState icon={FileCheck2} title="No audit events for this tenant yet." body="Actions taken in this tenant will appear here." />} />
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

  const linkedRunId = entity ? getString(entity, ['test_run_id', 'run_id'], '') : '';
  const [runContext, setRunContext] = useState<{ runId: string; status: 'idle' | 'loading' | 'loaded' | 'denied' | 'unavailable'; run: DataItem | null }>({ runId: '', status: 'idle', run: null });
  const [runContextReload, setRunContextReload] = useState(0);

  useEffect(() => {
    if (!linkedRunId) {
      setRunContext({ runId: '', status: 'idle', run: null });
      return undefined;
    }
    let cancelled = false;
    setRunContext({ runId: linkedRunId, status: 'loading', run: null });
    requestJson(config, session, `/v1/test-runs/${encodeURIComponent(linkedRunId)}`)
      .then((payload) => {
        if (cancelled) return;
        const run = payload && typeof payload === 'object' && !Array.isArray(payload) ? payload as DataItem : null;
        setRunContext({ runId: linkedRunId, status: run ? 'loaded' : 'unavailable', run });
      })
      .catch((err) => {
        if (cancelled) return;
        const status = Number((err as { status?: unknown })?.status ?? 0);
        setRunContext({ runId: linkedRunId, status: status === 403 ? 'denied' : 'unavailable', run: null });
      });
    return () => { cancelled = true; };
  }, [linkedRunId, config, session, runContextReload]);

  if (!entityId) {
    return (
      <div className="content">
        <DetailPageHeader
          route="evidence-detail"
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
        <DetailPageIntro route="evidence-detail" />
        <DetailLoadingPlaceholder label="Loading evidence artifact…" />
      </div>
    );
  }

  if (!entity) {
    return (
      <div className="content">
        <DetailPageHeader
          route="evidence-detail"
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
          ? `Verified by the server${integrityState.verifiedAt ? ` ${formatTimestamp(integrityState.verifiedAt)}` : ''}${integrityState.method ? ` · ${integrityState.method}` : ''}`
          : integrityState.value === 'not_verified'
            ? 'Not verified: no authoritative verification succeeded'
            : integrityState.value === 'recorded_digest'
              ? 'Not verified (recorded hash only)'
              : 'Not verified (no hash or verification recorded)';

  const artifactRecord = evidenceCodeBlock([
    ['artifact_id', artifactId],
    ['kind', kind],
    ['produced_by', producedBy],
    ['recorded_at', recordedAtRaw],
    ['sealed_at', sealedAtRaw],
  ]);

  const runContextCurrent = runContext.runId === runId;
  const runRecord = runContextCurrent && runContext.status === 'loaded' ? runContext.run : null;
  const runContextStatus = !runId ? 'idle' : runContextCurrent ? runContext.status : 'loading';
  const relationFallback = runContextStatus === 'denied'
    ? 'Not visible to your role'
    : runContextStatus === 'unavailable'
      ? 'Unavailable'
      : runContextStatus === 'loading'
        ? 'Reading the linked run…'
        : 'Relationship not recorded';
  const supportTargetId = getString(runRecord, ['target_id'], '') || getString(entity, ['target_id'], '');
  const supportCheckId = getString(runRecord, ['check_id'], '') || getString(entity, ['check_id'], '');
  const supportHost = supportTargetId ? getString(runRecord, ['target_value'], '') || targetDisplayLabel(data.targets, supportTargetId) : '';
  const supportCheckName = supportCheckId ? checkDisplayName(data.checks, supportCheckId) : '';
  const supportVerdict = runRecord && hasEvidenceBackedVerdict(runRecord, data.evidence) ? runVerdictValue(runRecord) : '';
  const supportFinding = findingId ? data.findings.find((finding) => getString(finding, ['id'], '') === findingId) ?? null : null;
  const evidenceTitle = supportCheckId && supportTargetId
    ? `${supportCheckName} result on ${supportHost}`
    : plainCodeLabel(kind, 'Evidence artifact');
  const evidenceBackLink: DetailListLink | undefined = findingId
    ? { label: 'finding', href: buildDetailHref('finding-detail', findingId) }
    : runId
      ? { label: 'run', href: buildDetailHref('run-detail', runId) }
      : undefined;

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
        entityId={artifactId}
        title={evidenceTitle}
        backLink={evidenceBackLink}
        description={<>One recorded artifact. {findingId
          ? 'It is referenced by the finding linked above.'
          : data.findingsMeta && !data.findingsMeta.hasMore
            ? 'No finding references this artifact explicitly.'
            : `No finding among the ${formatNumber(data.findings.length)} newest loaded findings references this artifact; older findings were not checked.`}</>}
        actions={(
          <>
            {payloadJson ? <Button size="sm" variant="ghost" loading={busy === 'verify'} disabled={busy !== ''} onClick={() => void recomputeDigest()}>Compute local digest</Button> : null}
            <Button size="sm" variant="secondary" loading={busy === 'export'} disabled={busy !== ''} onClick={() => void exportArtifact()}>Export artifact JSON</Button>
          </>
        )}
      />
      <CustomerPageStyles />
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
          <CardTitle>What this evidence supports</CardTitle>
          <CardDescription>Recorded relationships only. Nothing here is inferred from the artifact's contents.</CardDescription>
        </CardHeader>
        <CardContent className="stack-tight">
          {runContextStatus === 'loading' ? <p className="muted small" role="status">Reading the linked run…</p> : null}
          {runContextStatus === 'unavailable' ? (
            <div className="form-banner error row-actions" role="alert">
              <span>The linked run could not be loaded, so its target and check are not shown.</span>
              <Button size="sm" variant="secondary" onClick={() => setRunContextReload((count) => count + 1)}>Retry</Button>
            </div>
          ) : null}
          <div className="kv-list">
            <div><span>Target</span>{supportTargetId ? <DetailEntityLink route="target-detail" id={supportTargetId} label={supportHost} /> : <strong className="muted">{relationFallback}</strong>}</div>
            <div><span>Check</span>{supportCheckId ? <DetailEntityLink route="check-detail" id={supportCheckId} label={supportCheckName} /> : <strong className="muted">{relationFallback}</strong>}</div>
            <div><span>Run</span>{runId ? <DetailEntityLink route="run-detail" id={runId} /> : <strong className="muted">Relationship not recorded</strong>}</div>
            {supportVerdict ? <div><span>Recorded verdict</span><VerdictBadge value={supportVerdict} tone={verdictTone(supportVerdict)} /></div> : null}
            {findingId ? <div><span>Finding</span><DetailEntityLink route="finding-detail" id={findingId} label={supportFinding ? plainFindingTitle(supportFinding, data.targets, data.checks) : findingId} /></div> : null}
          </div>
        </CardContent>
      </Card>
      <Card>
        <CardHeader>
          <CardTitle>Integrity</CardTitle>
          <CardDescription>Each state is separate. A recorded hash alone does not prove custody.</CardDescription>
        </CardHeader>
        <CardContent className="kv-list">
          <div><span>Recorded hash</span><strong className="cp-mono-wrap">{sha256 || 'Not recorded'}</strong></div>
          <div><span>Locally computed (this page)</span><strong className="cp-mono-wrap">{localDigest ? `${localDigest.value} · ${formatTimestamp(localDigest.at)}, over displayed JSON only` : 'Not computed'}</strong></div>
          <div>
            <span>Server verification</span>
            <strong>
              {serverVerificationLabel}
              {integrityState.status === 'unavailable' ? <> <button type="button" className="rf-link-button" onClick={() => setIntegrityReload((count) => count + 1)}>Retry</button></> : null}
            </strong>
          </div>
          {sealedAtRaw ? <div><span>Sealed</span><strong>{formatTimestamp(sealedAtRaw)}</strong></div> : null}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Artifact</CardTitle>
          <CardDescription>Recorded fields only.</CardDescription>
        </CardHeader>
        <CardContent className="kv-list">
          <div><span>Kind</span><strong>{plainCodeLabel(kind, 'Not recorded')}</strong></div>
          <div><span>Recorded by run</span>{runId ? <DetailEntityLink route="run-detail" id={runId} /> : <strong>Not recorded</strong>}</div>
          <div><span>Size</span><strong>{sizeLabel || 'Not recorded'}</strong></div>
          <div><span>Recorded</span><strong>{recordedAtRaw ? formatTimestamp(recordedAtRaw) : 'Not recorded'}</strong></div>
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
  const [fingerprintState, setFingerprintState] = useState<Record<string, { status: 'hashing' | 'error'; message: string }>>({});
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

  async function fingerprintFile(type: string, file: File | undefined) {
    if (!file || !canWriteHighScale) return;
    setFingerprintState((current) => ({ ...current, [type]: { status: 'hashing', message: '' } }));
    try {
      if (typeof crypto === 'undefined' || !crypto.subtle) {
        throw new Error('This browser cannot fingerprint files here (Web Crypto is unavailable on this connection). Enter the SHA-256 manually.');
      }
      const hex = await sha256HexBytes(await file.arrayBuffer());
      updateDraft(type, 'filename', file.name);
      updateDraft(type, 'content_sha256', hex);
      setFingerprintState((current) => {
        const next = { ...current };
        delete next[type];
        return next;
      });
    } catch (err) {
      setFingerprintState((current) => ({
        ...current,
        [type]: { status: 'error', message: err instanceof Error ? err.message : 'The file could not be fingerprinted. Enter the SHA-256 manually.' }
      }));
    }
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
        setError('A SHA-256 fingerprint of the artifact file is required. Choose the file to fingerprint it, or enter the digest. Files are fingerprinted in your browser; file contents are never uploaded.');
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
  const domains = requestDomainDisplay(data, entity);
  const firstContact = emergencyContactRows(entity)[0] ?? null;
  const socApprovals = Array.isArray(entity.soc_approvals) ? entity.soc_approvals as DataItem[] : [];
  const adapterRecord = getNestedItem(entity, ['adapter']) ?? getNestedItem(entity, ['adapter_json']);
  const requestGates = [
    { label: 'Authorization pack accepted', pass: packOverall === 'accepted', detail: formatStatusLabel(packOverall, 'missing') },
    { label: 'Requested safe window recorded', pass: Boolean(requestedWindowStart && requestedWindowEnd), detail: requestedWindowStart && requestedWindowEnd ? `${formatDate(requestedWindowStart)} to ${formatDate(requestedWindowEnd)}` : 'window incomplete' },
    { label: 'Scope hash recorded', pass: Boolean(scopeHash), detail: scopeHash ? 'scope hash present' : 'not returned' },
    { label: 'SOC approval recorded', pass: socApprovals.length > 0, detail: `${socApprovals.length} approval record${socApprovals.length === 1 ? '' : 's'}` }
  ];

  return (
    <div className="content">
      <DetailPageHeader
        route="queue-detail"
        entityId={entityId}
        title={title}
        backLink={{ label: 'test runs', href: '#runs' }}
        actions={packOverall === 'accepted'
          ? <StatusBadge value={['submitted', 'under_review', 'approved'].includes(requestState) ? 'Waiting for SOC scheduling' : requestState} tone={highScaleStateTone(requestState)} fallback="submitted" />
          : <Button size="sm" variant="default" onClick={() => setTab('authorization')}>{canWriteHighScale ? 'Complete authorization pack' : 'View authorization pack'}</Button>}
      />
      <PageContextSummary>
        <StatusBadge value={requestState} tone={highScaleStateTone(requestState)} fallback="submitted" /> · pack{' '}
        <StatusBadge value={packOverall} tone={artifactReviewTone(packOverall)} fallback="missing" />
      </PageContextSummary>
      <p className="muted small">
        AstraNull SOC reviews, schedules, starts and stops this test. You cannot start it from the portal. To request an immediate stop, contact your SOC emergency contact or open <a href="#support">Support</a>.
        {firstContact ? ` Emergency contact on record: ${[firstContact.name, firstContact.detail].filter(Boolean).join(' · ') || 'name not recorded'}.` : ''}
      </p>
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
            <MetricCard label="State" value={formatStatusLabel(requestState)} sub="Governed request lifecycle" icon={ShieldCheck} tone={highScaleStateTone(requestState)} />
            <MetricCard label="Authorization" value={formatStatusLabel(packOverall, 'missing')} sub={`${artifacts.length} artifact records`} icon={FileCheck2} tone={packOverall === 'accepted' ? 'success' : 'warn'} />
            <MetricCard label="Scope" value={domains.length === 0 ? 'Domain scope not recorded' : domains.length === 1 ? domains[0] : `${formatNumber(domains.length)} domains`} sub={scopeHash ? 'scope hash recorded' : 'scope hash not returned'} icon={Target} tone="muted" />
            <MetricCard label="Window" value={requestedWindowStart ? formatDate(requestedWindowStart) : '—'} sub={requestedWindowEnd ? `through ${formatDate(requestedWindowEnd)}` : 'requested window incomplete'} icon={Activity} tone="muted" />
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
                    <CardDescription>Recorded customer request and the governed scope SOC reviews before scheduling.</CardDescription>
                  </CardHeader>
                  <CardContent className="kv-list">
                    <div><span>Request</span><strong title={entityId}>{title}</strong></div>
                    <div><span>State</span><StatusBadge value={requestState} tone={highScaleStateTone(requestState)} fallback="submitted" /></div>
                    <div><span>Reason</span><strong>{getString(entity, ['reason'], 'Not recorded')}</strong></div>
                    <div><span>Objective</span><strong>{getString(entity, ['objective'], 'Not recorded')}</strong></div>
                    <div><span>Requested by</span><strong>{getString(entity, ['created_by', 'requested_by'], 'Not recorded')}</strong></div>
                    <div><span>Created</span><strong>{formatDate(entity.created_at)}</strong></div>
                    <GovernedScopeRows entity={entity} domains={domains} />
                    {scopeHash ? <div><span>Scope hash</span><strong title={scopeHash}>Recorded</strong></div> : null}
                  </CardContent>
                </Card>
                <Card>
                  <CardHeader>
                    <CardTitle>Gate chain</CardTitle>
                    <CardDescription>Recorded prerequisites. SOC still revalidates scope, window, and authorization before execution.</CardDescription>
                  </CardHeader>
                  <CardContent>
                    <ul className="placement-gates gates-stacked" aria-label="High-scale request gates">
                      {requestGates.map((gate) => (
                        <li key={gate.label}>
                          {gate.pass ? <ShieldCheck size={14} aria-hidden="true" /> : <CircleDashed size={14} aria-hidden="true" />}
                          <span className="gate-text"><span>{gate.label}</span><span className="muted small">{plainInlineText(gate.detail)}</span></span>
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
                      <div><span>Adapter state</span><strong>{getString(adapterRecord, ['state'], 'Not returned')}</strong></div>
                      <div><span>Traffic generated</span><strong>{getString(adapterRecord, ['traffic_generated'], 'Not returned')}</strong></div>
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
              <CardHeader><CardTitle>Authorization artifacts</CardTitle><CardDescription>Record a metadata reference for each artifact for SOC review. Files are fingerprinted in your browser; file contents are never uploaded.</CardDescription></CardHeader>
              <CardContent className="stack-tight">
                <p className="small" role="status"><strong>{summarizeAuthorizationPackProgress(packStatus, requiredArtifactTypes)}</strong></p>
                <div className="artifact-upload-grid">
                  {requiredArtifactTypes.map((type) => {
                    const draft = draftForType(type);
                    const bestArtifact = bestArtifactForType(artifacts, type);
                    const requirement = packRequirementForType(packStatus, type);
                    const uploadBusy = busy === `upload-${type}`;
                    const fingerprint = fingerprintState[type];
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
                          {canWriteHighScale ? (
                            <label className="full">
                              <span>Choose file to fingerprint</span>
                              <input
                                type="file"
                                disabled={fingerprint?.status === 'hashing' || busy !== ''}
                                aria-describedby={fingerprint?.status === 'error' ? `fingerprint-error-${type}` : undefined}
                                onChange={(event) => {
                                  void fingerprintFile(type, event.target.files?.[0]);
                                  event.target.value = '';
                                }}
                              />
                              {fingerprint?.status === 'hashing' ? <small className="muted" role="status">Fingerprinting in your browser…</small> : null}
                              {fingerprint?.status === 'error' ? <small className="field-error" id={`fingerprint-error-${type}`} role="alert">{fingerprint.message}</small> : null}
                            </label>
                          ) : null}
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
                              <StatusBadge value={artifactStatus} tone={artifactReviewTone(artifactStatus)} fallback="pending_review" />
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
              <CardHeader><CardTitle>Lifecycle trail</CardTitle><CardDescription>Ordered request transitions and the actor recorded for each.</CardDescription></CardHeader>
              <CardContent><TimelinePanel items={lifecycleTrail.map((event) => ({ label: formatStatusLabel(event.action), at: event.at, by: event.by }))} /></CardContent>
            </Card></div>
          ) : null}

          {tab === 'provider' ? (
            <div role="tabpanel" id="high-scale-request-sections-panel-provider" aria-labelledby="high-scale-request-sections-tab-provider" className="tab-panel"><Card>
              <CardHeader><CardTitle>Provider checklist</CardTitle><CardDescription>Provider requirements and review states recorded for this request; no live provider telemetry is inferred.</CardDescription></CardHeader>
              <CardContent>
                {providerChecklist.length === 0 ? <EmptyState icon={ClipboardList} title="No provider checklist returned." body="No provider approval records are available for this request." /> : (
                  <div className="kv-list">
                    {providerChecklist.map((item, index) => (
                      <div key={getString(item, ['id'], String(index))}>
                        <span>{getString(item, ['label', 'provider_name', 'requirement'], 'Provider requirement')}</span>
                        <strong>
                          <StatusBadge value={getString(item, ['status'], 'Not recorded')} tone={getString(item, ['status'], '') ? artifactReviewTone(getString(item, ['status'], '')) : 'muted'} fallback="Not recorded" />
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


function socStartBlockedReason(failing: string[]) {
  return `Start stays disabled until every request gate passes. Not yet passing: ${failing.join(', ')}.`;
}

const SOC_ADAPTER_POLL_MS = 12_000;

type SocRequestGate = { label: string; pass: boolean; detail: string };

function distinctSocApprovers(entity: DataItem) {
  const approvals = Array.isArray(entity.soc_approvals) ? entity.soc_approvals as DataItem[] : [];
  return new Set(approvals.map((approval) => getString(approval, ['user_id'], '')).filter(Boolean)).size;
}

function summarizeRecordedCriteria(value: unknown): string {
  if (typeof value === 'string') return value.trim();
  if (Array.isArray(value)) return value.map((entry) => summarizeRecordedCriteria(entry)).filter(Boolean).join(' · ');
  if (!value || typeof value !== 'object') return '';
  return Object.entries(value as DataItem)
    .filter(([, entry]) => entry !== null && entry !== undefined && entry !== '')
    .map(([key, entry]) => {
      const rendered = typeof entry === 'boolean'
        ? (entry ? 'yes' : 'no')
        : typeof entry === 'object' ? summarizeRecordedCriteria(entry) : plainCodeLabel(String(entry), String(entry));
      return `${formatStatusLabel(key)}: ${rendered}`;
    })
    .join(' · ');
}

function emergencyContactRows(entity: DataItem) {
  const contacts = Array.isArray(entity.emergency_contacts) ? entity.emergency_contacts : [];
  return contacts
    .filter((contact): contact is DataItem => Boolean(contact && typeof contact === 'object' && !Array.isArray(contact)))
    .map((contact) => {
      const name = getString(contact, ['name', 'contact_name'], '');
      const role = getString(contact, ['role', 'title'], '');
      const detail = getString(contact, ['contact', 'email', 'phone'], '');
      return { name, role, detail };
    });
}

function viewerTimeZone() {
  try {
    return Intl.DateTimeFormat().resolvedOptions().timeZone || '';
  } catch {
    return '';
  }
}

function formatWindowRange(start: string, end: string, requestTimezone?: string) {
  if (!start || !end) return '';
  const range = `${formatTimestamp(start)} – ${formatTimestamp(end)}`;
  const zone = String(requestTimezone ?? '').trim();
  if (!zone || zone === viewerTimeZone()) return range;
  return `${range} · customer timezone ${zone}`;
}

function domainCountLabel(domains: string[]) {
  if (domains.length === 0) return 'Domain scope not recorded';
  return domains.length === 1 ? domains[0] : `${formatNumber(domains.length)} domains`;
}

function GovernedScopeRows({ entity, domains, includeScheduled = true }: { entity: DataItem; domains: string[]; includeScheduled?: boolean }) {
  const scenarios = Array.isArray(entity.requested_scenario_families) ? (entity.requested_scenario_families as unknown[]).map(String).filter(Boolean) : [];
  const patterns = Array.isArray(entity.delivery_patterns) ? (entity.delivery_patterns as unknown[]).map(String).filter(Boolean) : [];
  const limits = governedLimitDisplay(entity);
  const requestedStart = getNestedString(entity, ['requested_window', 'window_start'], '');
  const requestedEnd = getNestedString(entity, ['requested_window', 'window_end'], '');
  const requestedTimezone = getNestedString(entity, ['requested_window', 'timezone'], '');
  const scheduledStart = getNestedString(entity, ['scheduled_window', 'window_start'], '');
  const scheduledEnd = getNestedString(entity, ['scheduled_window', 'window_end'], '');
  const scheduledTimezone = getNestedString(entity, ['scheduled_window', 'timezone'], '') || requestedTimezone;
  const contacts = emergencyContactRows(entity);
  const abortSummary = summarizeRecordedCriteria(entity.abort_criteria);
  return (
    <>
      <div>
        <span>Domains</span>
        {domains.length ? (
          <span className="stack-tight">{domains.map((domain) => <code key={domain} className="mono">{domain}</code>)}</span>
        ) : <span className="muted">Not recorded</span>}
      </div>
      <RecordedKvRow label="Scenario families" value={scenarios.map(governedScenarioLabel).join(', ')} />
      <RecordedKvRow label="Delivery patterns" value={patterns.map((pattern) => formatStatusLabel(pattern)).join(', ')} />
      <RecordedKvRow label="Governed limits" value={limits === '—' ? '' : limits} />
      <RecordedKvRow label="Requested window" value={formatWindowRange(requestedStart, requestedEnd, requestedTimezone)} />
      {includeScheduled ? <RecordedKvRow label="Scheduled window" value={formatWindowRange(scheduledStart, scheduledEnd, scheduledTimezone)} missing="Not scheduled" /> : null}
      <div>
        <span>Emergency contacts</span>
        {contacts.length ? (
          <span className="stack-tight">
            <strong>{formatNumber(contacts.length)} {pluralize(contacts.length, 'contact')}</strong>
            {contacts.map((contact, index) => (
              <span key={`${contact.name}-${index}`} className="muted small">{[contact.name || 'Name not recorded', contact.role].filter(Boolean).join(' · ')}</span>
            ))}
          </span>
        ) : <span className="muted">Not recorded</span>}
      </div>
      <RecordedKvRow label="Abort criteria" value={abortSummary} />
    </>
  );
}

function SocRequestDetailView({
  entity,
  entityId,
  data,
  config,
  session,
  onRefresh,
  tenantId: tenantIdProp
}: {
  entity: DataItem;
  entityId: string;
  data: PortalData;
  config: PortalConfig;
  session: Session;
  onRefresh: () => Promise<void>;
  /** Cross-tenant staff SOC scope (from Open link query or entity.tenant_id). */
  tenantId?: string;
}) {
  const { confirm, confirmWithReason } = useConfirmModal();
  const [tab, setTab] = useState('workspace');
  const [busy, setBusy] = useState('');
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');
  const [adapterStatus, setAdapterStatus] = useState<DataItem | null>(null);
  const [adapterUpdatedAt, setAdapterUpdatedAt] = useState('');
  const [adapterPollError, setAdapterPollError] = useState('');
  const [socNotes, setSocNotes] = useState<DataItem[]>([]);
  const [notesLoading, setNotesLoading] = useState(false);
  const [notesError, setNotesError] = useState('');
  const [postTestReport, setPostTestReport] = useState<DataItem | null>(null);
  const [reportBusy, setReportBusy] = useState(false);
  const [postTestReportError, setPostTestReportError] = useState('');
  const [killSwitch, setKillSwitch] = useState<{ status: 'loading' | 'ready' | 'error'; active: boolean }>({ status: 'loading', active: false });
  const [scopeTargets, setScopeTargets] = useState<DataItem[]>([]);
  const [scheduleDraft, setScheduleDraft] = useState<{ start: string; end: string }>({ start: '', end: '' });
  const staffSocSurface = session.principal === 'staff' && isStaffSocRole(session);
  const isSoc = staffSocSurface || (session.role === 'soc' && session.principal !== 'staff');
  const actionTenantId =
    String(tenantIdProp ?? '').trim()
    || getString(entity, ['tenant_id'], '')
    || session.tenant_id
    || undefined;
  const state = getString(entity, ['state'], '');

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
      if ((err as { status?: number }).status === 404) {
        setPostTestReportError('');
        return;
      }
      setPostTestReportError(apiErrorMessage(err, 'Post-test report status could not be loaded.'));
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
  const domains = requestDomainDisplay({ targets: scopeTargets.length ? scopeTargets : data.targets }, entity);
  const governedLimits = governedLimitDisplay(entity);
  const requestedWindowStart = getNestedString(entity, ['requested_window', 'window_start'], '');
  const requestedWindowEnd = getNestedString(entity, ['requested_window', 'window_end'], '');
  const requestedTimezone = getNestedString(entity, ['requested_window', 'timezone'], '');
  const windowStart = getNestedString(entity, ['scheduled_window', 'window_start'], '');
  const windowEnd = getNestedString(entity, ['scheduled_window', 'window_end'], '');
  const letterWindow = authorizationLetterValidWindow(entity);
  const scheduleDefault = defaultScheduleWindow(entity);
  const scheduleDraftKey = useRef('');
  const requiredArtifactTypes = authorizationArtifactTypesForRequest(entity);
  const otherArtifacts = artifacts.filter((artifact) => !(requiredArtifactTypes as readonly string[]).includes(getString(artifact, ['type'], '')));
  const requiredAccepted = requiredArtifactTypes.filter((type) => getString(packRequirementForType(packStatus, type) ?? {}, ['status'], '') === 'accepted').length;
  const startedAt = [...lifecycleTrail].reverse().find((event) => event.action === 'start')?.at ?? '';
  const tabOptions = [
    { id: 'workspace', label: 'Workspace' },
    { id: 'artifacts', label: 'Artifacts' },
    { id: 'provider', label: 'Provider' },
    { id: 'adapter', label: 'Adapter' },
    { id: 'notes', label: 'Notes' }
  ];

  function scopeSummary(windowLine: ReactNode) {
    return (
      <div className="stack-tight">
        <p><strong>{title}</strong> · tenant {actionTenantId ? <code>{actionTenantId}</code> : 'not recorded'}</p>
        <p>Domains: {domains.length === 0 ? 'domain scope not recorded' : domains.length <= 3 ? domains.join(', ') : `${formatNumber(domains.length)} domains`}</p>
        <p>Governed limits: {governedLimits === '—' ? 'not recorded' : governedLimits}</p>
        <p>{windowLine}</p>
      </div>
    );
  }

  function lifecycleConfirmRequest(action: string, body: Record<string, unknown>) {
    if (action === 'start') {
      return {
        title: 'Start governed traffic',
        description: (
          <>
            {scopeSummary(windowEnd ? `Scheduled window ends ${formatTimestamp(windowEnd)}.` : 'Scheduled window end not recorded.')}
            <p>Governed adapter traffic will begin against these domains.</p>
          </>
        ),
        confirmLabel: 'Start traffic',
        confirmTone: 'danger' as const,
        requireTypedId: entityId
      };
    }
    if (action === 'approve') {
      return {
        title: 'Approve governed request',
        description: (
          <>
            {scopeSummary(requestedWindowStart && requestedWindowEnd ? `Customer-requested window ${formatWindowRange(requestedWindowStart, requestedWindowEnd, requestedTimezone)}.` : 'Customer-requested window not recorded.')}
            <p>All required authorization artifacts and provider approvals are accepted.</p>
          </>
        ),
        confirmLabel: 'Approve',
        confirmTone: 'default' as const
      };
    }
    if (action === 'schedule') {
      const start = String(body.window_start ?? '');
      const end = String(body.window_end ?? '');
      const zone = viewerTimeZone();
      return {
        title: 'Schedule governed request',
        description: (
          <>
            <p>Schedule {title} for {formatTimestamp(start)} – {formatTimestamp(end)}, inside the customer-requested window {formatTimestamp(requestedWindowStart)} – {formatTimestamp(requestedWindowEnd)}?</p>
            <p className="muted small">Times are shown in your timezone{zone ? ` (${zone})` : ''}{requestedTimezone && requestedTimezone !== zone ? `; the customer requested this window in ${requestedTimezone}` : ''}.</p>
          </>
        ),
        confirmLabel: 'Schedule',
        confirmTone: 'default' as const
      };
    }
    if (action === 'stop') {
      return {
        title: 'Stop governed traffic',
        description: `Stop governed high-scale traffic for ${title} now? The adapter is told to stop immediately and the request moves to stopped.`,
        confirmLabel: 'Stop traffic',
        confirmTone: 'danger' as const
      };
    }
    if (action === 'close') {
      return {
        title: 'Close governed request',
        description: `Close ${title} and finalize the governed test lifecycle? A closed request cannot be restarted.`,
        confirmLabel: 'Close request',
        confirmTone: 'danger' as const
      };
    }
    return null;
  }

  async function socAction(action: string, body: Record<string, unknown> = {}) {
    const request = lifecycleConfirmRequest(action, body);
    if (request && !(await confirm(request))) return false;
    setBusy(`${action}-${entityId}`);
    setError('');
    setMessage('');
    try {
      await socFetch(`/internal/soc/high-scale/${encodeURIComponent(entityId)}/${action}`, { method: 'POST', body });
      setMessage(action === 'notes' ? 'SOC note added.' : action.startsWith('artifacts/') ? 'Artifact review recorded.' : `SOC ${action} completed.`);
      await onRefresh();
      return true;
    } catch (err) {
      setError(apiErrorMessage(err, 'SOC action failed.'));
      return false;
    } finally {
      setBusy('');
    }
  }

  async function reviewArtifact(artifactId: string, type: string, status: 'accepted' | 'rejected') {
    if (status === 'accepted') {
      if (!await confirm({
        title: 'Accept authorization artifact',
        description: `Accept ${authorizationArtifactTitle(type)}? Execution still requires every required artifact to be accepted (${requiredAccepted}/${requiredArtifactTypes.length} accepted now).`,
        confirmLabel: 'Accept artifact',
        confirmTone: 'default'
      })) return;
      await socAction(`artifacts/${artifactId}/review`, { status, notes: null });
      return;
    }
    const reason = await confirmWithReason({
      title: `Reject ${authorizationArtifactTitle(type)}?`,
      description: 'The customer sees this reason on their authorization pack and must record corrected metadata before SOC can approve.',
      confirmLabel: 'Reject artifact',
      confirmTone: 'danger',
      reason: { label: 'Reason shown to the customer', required: true }
    });
    if (reason === null) return;
    await socAction(`artifacts/${artifactId}/review`, { status, notes: reason.trim() });
  }

  function renderArtifactReview(artifact: DataItem, type: string, requirement: DataItem | null, role: 'current' | 'earlier' | 'extra') {
    const artifactId = getString(artifact, ['id'], '');
    const artifactStatus = getString(artifact, ['status'], 'pending_review');
    const reviewBusy = busy === `artifacts/${artifactId}/review-${entityId}`;
    const validFrom = getNestedString(artifact, ['valid_window', 'window_start'], '') || getNestedString(artifact, ['valid_window', 'valid_from'], '');
    const validTo = getNestedString(artifact, ['valid_window', 'window_end'], '') || getNestedString(artifact, ['valid_window', 'valid_to'], '');
    const approvedTargets = Array.isArray(artifact.approved_targets) ? (artifact.approved_targets as unknown[]).length : null;
    const reviewedBy = getString(artifact, ['reviewed_by'], '');
    const reviewedAt = getString(artifact, ['reviewed_at'], '');
    const reviewNotes = getString(artifact, ['review_notes'], '');
    const lastReview = reviewedBy || reviewedAt
      ? [reviewedBy, reviewedAt ? formatTimestamp(reviewedAt) : '', reviewNotes].filter(Boolean).join(' · ')
      : '';
    const heading = role === 'earlier'
      ? `${authorizationArtifactTitle(type)} · earlier upload`
      : type ? authorizationArtifactTitle(type) : 'Untyped artifact';
    return (
      <div key={artifactId || `${type}-${role}`} className="kv-stack" data-testid="soc-artifact-review-row">
        <span>{heading}</span>
        <div className="stack-tight">
          <div className="row-actions">
            <StatusBadge value={artifactStatus} tone={artifactReviewTone(artifactStatus)} />
            {artifactStatus === 'pending_review' ? (
              <Button size="sm" variant="secondary" loading={reviewBusy} disabled={busy !== ''} onClick={() => void reviewArtifact(artifactId, type, 'accepted')}>Accept</Button>
            ) : null}
            {artifactStatus === 'pending_review' || artifactStatus === 'accepted' ? (
              <Button size="sm" variant="ghost" loading={reviewBusy} disabled={busy !== ''} onClick={() => void reviewArtifact(artifactId, type, 'rejected')}>{artifactStatus === 'accepted' ? 'Revoke (reject)' : 'Reject'}</Button>
            ) : null}
          </div>
          <div className="kv-list">
            <RecordedKvRow label="Filename" value={getString(artifact, ['filename_redacted', 'filename'], '')} />
            <RecordedKvRow label="Uploaded by" value={getString(artifact, ['uploader', 'uploaded_by', 'created_by'], '')} mono />
            <RecordedKvRow label="Uploaded" value={getString(artifact, ['created_at', 'uploaded_at'], '') ? formatTimestamp(getString(artifact, ['created_at', 'uploaded_at'], '')) : ''} />
            <RecordedKvRow label="Approver" value={getString(artifact, ['approver'], '')} />
            <RecordedKvRow label="Approval reference" value={getString(artifact, ['approval_reference'], '')} mono />
            <RecordedKvRow label="Valid window" value={validFrom && validTo ? `${formatDate(validFrom)} to ${formatDate(validTo)}` : ''} />
            <RecordedKvRow label="Approved targets" value={approvedTargets === null ? '' : formatNumber(approvedTargets)} />
            <RecordedKvRow label="Custody ID" value={getString(artifact, ['custody_id'], '')} mono />
            <RecordedKvRow label="Reference" value={getString(artifact, ['reference_uri_redacted', 'reference_uri'], '')} mono />
            <RecordedKvRow label="SHA-256" value={getString(artifact, ['content_sha256'], '')} mono />
            <RecordedKvRow label="Last review" value={lastReview} missing="Not reviewed yet" />
          </div>
          {role === 'extra'
            ? <p className="muted small">Not part of the required authorization pack for this request.</p>
            : role === 'earlier'
              ? <p className="muted small">Superseded by the current upload above for pack status; still reviewable.</p>
              : <p className="muted small">{explainArtifactReviewStatus(type, requirement, artifact)}</p>}
        </div>
      </div>
    );
  }

  async function loadAdapterStatus() {
    setBusy(`adapter-${entityId}`);
    setError('');
    try {
      const payload = await socFetch(`/internal/soc/high-scale/${encodeURIComponent(entityId)}/adapter-status`);
      setAdapterStatus(payload as DataItem);
      setAdapterUpdatedAt(new Date().toISOString());
      setAdapterPollError('');
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
    const saved = await socAction('notes', { body });
    if (!saved) return;
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
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [entityId, isSoc]);

  useEffect(() => {
    if (!isSoc || !entityId || state !== 'stopped') {
      setPostTestReport(null);
      setPostTestReportError('');
      return;
    }
    void loadPostTestReport();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [entityId, isSoc, state]);

  useEffect(() => {
    if (!isSoc) return undefined;
    let cancelled = false;
    setKillSwitch((current) => ({ ...current, status: 'loading' }));
    socFetch('/v1/state')
      .then((payload) => {
        if (cancelled) return;
        const record = getNestedItem(payload as DataItem, ['kill_switch']);
        setKillSwitch({ status: record ? 'ready' : 'error', active: killSwitchActiveForTenant(record, actionTenantId) });
      })
      .catch(() => {
        if (!cancelled) setKillSwitch({ status: 'error', active: false });
      });
    return () => { cancelled = true; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isSoc, actionTenantId, entityId, state]);

  useEffect(() => {
    if (!isSoc) return undefined;
    let cancelled = false;
    socFetch('/v1/targets')
      .then((payload) => {
        if (cancelled) return;
        const items = payload && typeof payload === 'object' && Array.isArray((payload as { items?: unknown }).items)
          ? (payload as { items: DataItem[] }).items
          : [];
        setScopeTargets(items);
      })
      .catch(() => {
        if (!cancelled) setScopeTargets([]);
      });
    return () => { cancelled = true; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isSoc, actionTenantId]);

  useEffect(() => {
    const key = `${entityId}|${state}|${requestedWindowStart}|${requestedWindowEnd}`;
    if (scheduleDraftKey.current === key) return;
    scheduleDraftKey.current = key;
    setScheduleDraft(scheduleDefault
      ? { start: toDatetimeLocalValue(scheduleDefault.window_start), end: toDatetimeLocalValue(scheduleDefault.window_end) }
      : { start: '', end: '' });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [entityId, state, requestedWindowStart, requestedWindowEnd]);

  useEffect(() => {
    if (!isSoc || !entityId || state !== 'running') return undefined;
    let cancelled = false;
    const poll = () => {
      socFetch(`/internal/soc/high-scale/${encodeURIComponent(entityId)}/adapter-status`)
        .then((payload) => {
          if (cancelled) return;
          setAdapterStatus(payload as DataItem);
          setAdapterUpdatedAt(new Date().toISOString());
          setAdapterPollError('');
        })
        .catch((err) => {
          if (!cancelled) setAdapterPollError(apiErrorMessage(err, 'Adapter status could not be refreshed.'));
        });
    };
    poll();
    const timer = window.setInterval(poll, SOC_ADAPTER_POLL_MS);
    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isSoc, entityId, state, actionTenantId]);

  if (!isSoc) {
    const isStaffPrincipal = session.principal === 'staff';
    return (
      <div className="content">
        <DetailPageIntro route="queue-detail" context="SOC execution workspace" />
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

  const packReady = getNestedString(entity, ['authorization_pack_status', 'overall'], '') === 'accepted';
  const hasPostTestReport = Boolean(postTestReport && getString(postTestReport, ['id'], ''));
  const windowState = scheduledWindowState(windowStart, windowEnd);
  const scopeRecorded = Boolean(getString(entity, ['scope_hash'], '') || getNestedItem(entity, ['scope_confirmation']));
  const approverCount = distinctSocApprovers(entity);
  const stateTone = highScaleStateTone(state);
  const killSwitchGate: SocRequestGate = killSwitch.status === 'ready'
    ? { label: 'Tenant kill switch clear', pass: !killSwitch.active, detail: killSwitch.active ? 'Kill switch is active for this tenant: execution is blocked.' : 'Kill switch is not active for this tenant.' }
    : { label: 'Tenant kill switch clear', pass: false, detail: killSwitch.status === 'loading' ? 'Reading tenant kill-switch state…' : 'Kill-switch state could not be read.' };
  const preflightGates: SocRequestGate[] = [
    { label: 'Authorization pack accepted', pass: packReady, detail: formatStatusLabel(getString(packStatus ?? {}, ['overall'], 'missing'), 'missing') },
    {
      label: 'Inside scheduled safe window',
      pass: windowState === 'open',
      detail: windowState === 'open'
        ? `Open until ${formatTimestamp(windowEnd)}`
        : windowState === 'upcoming'
          ? `Opens ${formatTimestamp(windowStart)}`
          : windowState === 'expired'
            ? `Window ended ${formatTimestamp(windowEnd)}: reschedule required`
            : 'No scheduled window recorded'
    },
    { label: 'Scope hash recorded', pass: scopeRecorded, detail: scopeRecorded ? 'Scope binding recorded' : 'Scope binding not returned' },
    { label: `Two SOC approvals recorded (${Math.min(approverCount, 2)}/2)`, pass: approverCount >= 2, detail: `${formatNumber(approverCount)} distinct ${pluralize(approverCount, 'approver')}` },
    killSwitchGate
  ];
  const passedGates = preflightGates.filter((gate) => gate.pass).length;
  const preflightReady = passedGates === preflightGates.length;
  const startBlockedReason = preflightReady ? '' : socStartBlockedReason(preflightGates.filter((gate) => !gate.pass).map((gate) => gate.label));
  const windowKpi = windowState === 'open'
    ? { value: `Safe window open until ${formatTimestamp(windowEnd)}`, delta: 'Inside the scheduled window', tone: 'success' as const }
    : windowState === 'upcoming'
      ? { value: `Opens ${formatTimestamp(windowStart)}`, delta: 'Scheduled, not open yet', tone: 'muted' as const }
      : windowState === 'expired'
        ? { value: `Window expired ${formatTimestamp(windowEnd)}`, delta: 'Reschedule required', tone: (state === 'running' ? 'danger' : 'warn') as StatusBadgeTone }
        : { value: 'Unscheduled', delta: 'Awaiting schedule', tone: 'muted' as const };
  const scheduleStartIso = fromDatetimeLocalValue(scheduleDraft.start);
  const scheduleEndIso = fromDatetimeLocalValue(scheduleDraft.end);
  const scheduleErrors = scheduleWindowErrors(entity, { window_start: scheduleStartIso, window_end: scheduleEndIso });
  const scheduleStartError = scheduleErrors.filter((entry) => entry.field === 'window_start').map((entry) => entry.message).join(' ');
  const scheduleEndError = scheduleErrors.filter((entry) => entry.field === 'window_end').map((entry) => entry.message).join(' ');
  const requestedWindowState = scheduledWindowState(requestedWindowStart, requestedWindowEnd);
  const scheduleUnavailableReason = !requestedWindowStart || !requestedWindowEnd || requestedWindowState === 'unscheduled'
    ? 'The customer-requested window is not recorded, so this request cannot be scheduled. Ask the customer to submit a new request with a safe window.'
    : requestedWindowState === 'expired'
      ? `The customer-requested window ended ${formatTimestamp(requestedWindowEnd)}. This request cannot be scheduled; ask the customer to submit a new request with a current window.`
      : !scheduleDefault
        ? 'No part of the customer-requested window remains inside the authorization letter validity. Ask the customer to refresh the authorization letter.'
        : '';
  const viewerTimezone = viewerTimeZone() || 'your local time';
  const stopBusy = busy === `stop-${entityId}`;

  return (
    <div className="content">
      <DetailPageHeader route="queue-detail" context="SOC execution workspace" entityId={entityId} title={title} />
      <PageContextSummary>
        <StatusBadge value={state} tone={highScaleStateTone(state)} fallback="submitted" /> · tenant {actionTenantId ? <code>{actionTenantId}</code> : 'not recorded'}
      </PageContextSummary>
      <DetailStatusBanners error={error} message={message} hideMessageWhenLoadError={false} />
      {state === 'running' ? (
        <div className="form-banner error stack-tight" role="status" data-testid="soc-live-banner">
          <div className="row-actions">
            <Siren size={16} aria-hidden="true" />
            <strong>LIVE · Governed high-scale traffic is running</strong>
          </div>
          <p className="small">
            {domainCountLabel(domains)} · {windowEnd ? `Window ends ${formatTimestamp(windowEnd)}` : 'Window end not recorded'}
            {startedAt ? ` · Started ${formatTimestamp(startedAt)}` : ''}
          </p>
          <div className="row-actions">
            <Button variant="danger" loading={stopBusy} disabled={stopBusy} onClick={() => void socAction('stop')}>Stop now</Button>
            <AnchorButton variant="secondary" href="#internal-soc">Tenant kill switch</AnchorButton>
          </div>
          <p className="muted text-xs" aria-live="off">
            {adapterUpdatedAt ? `Adapter status updated ${formatTimestamp(adapterUpdatedAt)}` : 'Reading adapter status…'}
            {adapterPollError ? ` · Last refresh failed: ${adapterPollError}` : ''}
          </p>
        </div>
      ) : null}
      <div className="kpi-row" role="group" aria-label="Request summary">
        <KpiCell label="State" value={formatStatusLabel(state, 'submitted')} delta="Governed lifecycle state" tone={stateTone} />
        <KpiCell label="Pack" value={formatStatusLabel(getString(packStatus ?? {}, ['overall'], 'missing'), 'missing')} delta="Authorization pack review" tone={packReady ? 'success' : 'warn'} />
        <KpiCell label="Domains" value={domains.length === 0 ? 'Not recorded' : domains.length === 1 ? domains[0] : `${formatNumber(domains.length)} domains`} valueClassName={domains.length === 1 ? 'mono' : undefined} delta="Declared scope under request" tone="muted" />
        <KpiCell label="Window" value={windowKpi.value} delta={windowKpi.delta} tone={windowKpi.tone} />
      </div>
      {state === 'running' ? (
        <p className="muted small">Pre-flight gates: {passedGates}/{preflightGates.length} passed at start.</p>
      ) : (
        <Card>
          <CardHeader>
            <CardTitle>Request gates</CardTitle>
            <CardDescription>Pre-flight readiness derived from recorded request evidence. Every gate must pass before governed execution starts; the server rechecks each one.</CardDescription>
          </CardHeader>
          <CardContent>
            <ul className="placement-gates gates-stacked" aria-label="Request gates">
              {preflightGates.map((gate) => (
                <li key={gate.label}>
                  {gate.pass ? <ShieldCheck size={14} aria-hidden="true" /> : <CircleDashed size={14} aria-hidden="true" />}
                  <span className="gate-text"><span>{gate.label}</span><span className="muted small">{gate.detail}</span></span>
                  <Badge tone={gate.pass ? 'success' : 'warn'} aria-label={`${gate.label}: ${gate.pass ? 'pass' : 'pending'}`}>{gate.pass ? 'pass' : 'pending'}</Badge>
                </li>
              ))}
            </ul>
          </CardContent>
        </Card>
      )}
      <Card>
        <CardHeader>
          <CardTitle>Governed scope</CardTitle>
          <CardDescription>What this request authorizes, as recorded. Read it before approving, scheduling or starting.</CardDescription>
        </CardHeader>
        <CardContent className="kv-list">
          <GovernedScopeRows entity={entity} domains={domains} />
        </CardContent>
      </Card>
      <Tabs value={tab} options={tabOptions} onChange={setTab} className="tabs-wrap" ariaLabel="SOC queue detail sections"
            getTabId={(id) => `soc-queue-detail-sections-tab-${id}`}
            getPanelId={(id) => `soc-queue-detail-sections-panel-${id}`} />
      {tab === 'workspace' ? (
        <div role="tabpanel" id="soc-queue-detail-sections-panel-workspace" aria-labelledby="soc-queue-detail-sections-tab-workspace" className="tab-panel"><>
        <Card>
          <CardHeader><CardTitle>Queue context</CardTitle><CardDescription>Lifecycle actions for this request</CardDescription></CardHeader>
          <CardContent className="stack-tight">
            <div className="kv-list">
              <div><span>State</span><StatusBadge value={state} tone={highScaleStateTone(state)} /></div>
              <div><span>Pack</span><StatusBadge value={getString(packStatus ?? {}, ['overall'], 'missing')} tone={artifactReviewTone(getString(packStatus ?? {}, ['overall'], 'missing'))} fallback="missing" /></div>
            </div>
            <div className="row-actions">
              {['submitted', 'under_review'].includes(state) ? (
                <Button
                  size="sm"
                  variant="secondary"
                  loading={busy === `approve-${entityId}`}
                  disabled={busy !== '' || !packReady}
                  title={packReady ? undefined : 'Approval stays disabled until the authorization pack is accepted.'}
                  aria-describedby={packReady ? undefined : 'soc-approve-disabled-reason'}
                  onClick={() => void socAction('approve')}
                >Approve</Button>
              ) : null}
              {state === 'scheduled' ? <Button size="sm" variant="default" loading={busy === `start-${entityId}`} disabled={busy !== '' || !preflightReady} title={startBlockedReason || undefined} aria-describedby={preflightReady ? undefined : 'soc-start-disabled-reason'} onClick={() => void socAction('start')}>Start</Button> : null}
              {state === 'stopped' && hasPostTestReport ? <Button size="sm" variant="secondary" loading={busy === `close-${entityId}`} disabled={busy !== ''} onClick={() => void socAction('close')}>Close</Button> : null}
              {state === 'stopped' && !hasPostTestReport ? <Button size="sm" variant="secondary" disabled title={postTestReportError ? 'Post-test report status could not be loaded' : 'Attach a post-test report before closing'}>Close</Button> : null}
            </div>
            {['submitted', 'under_review'].includes(state) && !packReady ? (
              <p className="muted text-xs" id="soc-approve-disabled-reason">Approval stays disabled until the authorization pack is accepted (every required artifact and provider approval).</p>
            ) : null}
            {state === 'running' ? <p className="muted small">Stop this test from the live banner above.</p> : null}
            {state === 'approved' ? (
              scheduleUnavailableReason ? (
                <div className="form-banner neutral" role="note">{scheduleUnavailableReason}</div>
              ) : (
                <form
                  className="product-form"
                  aria-label="Schedule governed window"
                  onSubmit={(event) => {
                    event.preventDefault();
                    if (scheduleErrors.length || !scheduleStartIso || !scheduleEndIso) return;
                    void socAction('schedule', { window_start: scheduleStartIso, window_end: scheduleEndIso });
                  }}
                >
                  <div className="kv-list full">
                    <RecordedKvRow label="Customer-requested window" value={formatWindowRange(requestedWindowStart, requestedWindowEnd, requestedTimezone)} />
                    {letterWindow ? <RecordedKvRow label="Authorization letter valid" value={formatWindowRange(new Date(letterWindow.start).toISOString(), new Date(letterWindow.end).toISOString())} /> : null}
                  </div>
                  <label>
                    <span>Window start ({viewerTimezone})</span>
                    <input
                      type="datetime-local"
                      value={scheduleDraft.start}
                      required
                      aria-invalid={scheduleStartError ? true : undefined}
                      aria-describedby={scheduleStartError ? 'soc-schedule-start-error' : undefined}
                      onChange={(event) => setScheduleDraft((current) => ({ ...current, start: event.target.value }))}
                    />
                    {scheduleStartError ? <small className="field-error" id="soc-schedule-start-error">{scheduleStartError}</small> : null}
                  </label>
                  <label>
                    <span>Window end ({viewerTimezone})</span>
                    <input
                      type="datetime-local"
                      value={scheduleDraft.end}
                      required
                      aria-invalid={scheduleEndError ? true : undefined}
                      aria-describedby={scheduleEndError ? 'soc-schedule-end-error' : undefined}
                      onChange={(event) => setScheduleDraft((current) => ({ ...current, end: event.target.value }))}
                    />
                    {scheduleEndError ? <small className="field-error" id="soc-schedule-end-error">{scheduleEndError}</small> : null}
                  </label>
                  <div className="form-actions full">
                    <Button type="submit" size="sm" variant="secondary" loading={busy === `schedule-${entityId}`} disabled={busy !== '' || scheduleErrors.length > 0}>Schedule</Button>
                  </div>
                </form>
              )
            ) : null}
            {state === 'scheduled' && !preflightReady ? <p className="muted text-xs" id="soc-start-disabled-reason">{startBlockedReason}</p> : null}
            {state === 'stopped' && reportBusy ? <p className="muted small">Checking for an attached post-test report…</p> : null}
            {state === 'stopped' && !reportBusy && postTestReportError ? (
              <div className="form-banner error row-actions" role="alert">
                <span>Post-test report status could not be loaded. Closing remains disabled until report status can be confirmed.</span>
                <Button size="sm" variant="ghost" loading={reportBusy} onClick={() => void loadPostTestReport()}>Retry</Button>
              </div>
            ) : null}
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
            <CardHeader><CardTitle>Request facts</CardTitle><CardDescription>Tenant, purpose, and requester returned with this queue item.</CardDescription></CardHeader>
            <CardContent className="kv-list">
              <div><span>Request</span><strong title={entityId}>{title}</strong></div>
              <RecordedKvRow label="Tenant" value={actionTenantId ?? ''} mono />
              <RecordedKvRow label="Reason" value={getString(entity, ['reason'], '')} />
              <RecordedKvRow label="Objective" value={getString(entity, ['objective'], '')} />
              <RecordedKvRow label="Requested by" value={getString(entity, ['created_by', 'requested_by'], '')} mono />
              {getString(entity, ['scope_hash'], '') ? <div><span>Scope hash</span><strong title={getString(entity, ['scope_hash'], '')}>Recorded</strong></div> : null}
            </CardContent>
          </Card>
          <Card>
            <CardHeader><CardTitle>Lifecycle</CardTitle><CardDescription>Ordered request transitions and the actor recorded for each.</CardDescription></CardHeader>
            <CardContent><TimelinePanel items={lifecycleTrail.map((event) => ({ label: formatStatusLabel(event.action), at: event.at, by: event.by }))} /></CardContent>
          </Card>
        </div>
        </></div>
      ) : null}
      {tab === 'artifacts' ? (
        <div role="tabpanel" id="soc-queue-detail-sections-panel-artifacts" aria-labelledby="soc-queue-detail-sections-tab-artifacts" className="tab-panel"><Card>
          <CardHeader>
            <CardTitle>Authorization artifacts</CardTitle>
            <CardDescription>{summarizeAuthorizationPackProgress(packStatus, requiredArtifactTypes)}. Artifacts are metadata records; no file is stored or downloadable here.</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="kv-list">
              {requiredArtifactTypes.map((type) => {
                const uploads = orderedArtifactsForType(artifacts, type);
                const requirement = packRequirementForType(packStatus, type);
                if (uploads.length === 0) {
                  return (
                    <div key={type}>
                      <span>{authorizationArtifactTitle(type)}</span>
                      <div className="stack-tight">
                        <Badge tone="muted">Not uploaded</Badge>
                        <p className="muted small">{explainArtifactReviewStatus(type, requirement, null)}</p>
                      </div>
                    </div>
                  );
                }
                return uploads.map((artifact, index) => renderArtifactReview(artifact, type, requirement, index === 0 ? 'current' : 'earlier'));
              })}
              {otherArtifacts.length > 0 ? (
                <div className="kv-stack">
                  <span>Other uploaded artifacts</span>
                  <p className="muted small">{formatNumber(otherArtifacts.length)} {pluralize(otherArtifacts.length, 'artifact')} of a type this request does not require. Review them like any other upload; they do not count toward the authorization pack.</p>
                </div>
              ) : null}
              {otherArtifacts.map((artifact) => renderArtifactReview(artifact, getString(artifact, ['type'], ''), null, 'extra'))}
            </div>
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
                      <StatusBadge value={getString(item, ['status'], 'Not recorded')} tone={getString(item, ['status'], '') ? artifactReviewTone(getString(item, ['status'], '')) : 'muted'} fallback="Not recorded" />
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
          <CardHeader>
            <CardTitle>Adapter status</CardTitle>
            <CardDescription>{state === 'running' ? `Refreshed automatically every ${SOC_ADAPTER_POLL_MS / 1000} seconds while the test runs.` : 'Read on request. No provider telemetry is inferred.'}</CardDescription>
          </CardHeader>
          <CardContent>
            <Button size="sm" variant="secondary" loading={busy === `adapter-${entityId}`} disabled={busy !== ''} onClick={() => void loadAdapterStatus()}>Refresh adapter status</Button>
            {adapterStatus ? (
              <div className="kv-list">
                <div><span>State</span><strong>{getNestedString(adapterStatus, ['adapter', 'state'], getString(adapterStatus, ['state'], 'Not returned'))}</strong></div>
                <div><span>Traffic generated</span>{getNestedString(adapterStatus, ['adapter', 'traffic_generated'], '') ? <Badge tone={getNestedString(adapterStatus, ['adapter', 'traffic_generated'], '') === 'true' ? 'warn' : 'muted'}>{getNestedString(adapterStatus, ['adapter', 'traffic_generated'], '') === 'true' ? 'Yes' : 'No'}</Badge> : <strong>Not returned</strong>}</div>
                <div><span>Provider reference</span><strong>{getNestedString(adapterStatus, ['adapter', 'provider_reference'], getString(adapterStatus, ['provider_reference'], 'Not returned'))}</strong></div>
                {adapterUpdatedAt ? <div><span>Updated</span><strong>{formatTimestamp(adapterUpdatedAt)}</strong></div> : null}
              </div>
            ) : <p className="muted">Adapter status has not been requested. No provider telemetry is inferred.</p>}
          </CardContent>
        </Card></div>
      ) : null}
      {tab === 'notes' ? (
        <div role="tabpanel" id="soc-queue-detail-sections-panel-notes" aria-labelledby="soc-queue-detail-sections-tab-notes" className="tab-panel"><Card>
          <CardHeader><CardTitle>SOC notes</CardTitle><CardDescription>Timestamped record of execution context, customer coordination and stop rationale for this request. Notes are redacted and included in post-test and tenant report exports.</CardDescription></CardHeader>
          <CardContent>
            {notesLoading ? <DetailLoadingPlaceholder label="Loading SOC notes…" variant="compact" /> : null}
            {notesError ? <div className="form-banner error" role="alert">{notesError} No empty note history is being assumed.</div> : null}
            {socNotes.length > 0 ? (
              <div className="kv-list stack-tight">
                {socNotes.map((note, index) => (
                  <div key={getString(note, ['id'], String(index))}>
                    <span>{formatDate(note.created_at)} · {getString(note, ['author', 'created_by'], 'author not recorded')}</span>
                    <strong>{getString(note, ['body'])}</strong>
                  </div>
                ))}
              </div>
            ) : !notesLoading && !notesError ? <EmptyState icon={ClipboardList} title="No SOC notes recorded." body="Add execution context, customer coordination, or stop rationale below." /> : null}
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
    if (kind === 'remediation') return 'Review authorization, declared scope, and SOC prerequisites, then contact support to arrange this scenario with AstraNull SOC.';
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
  const [runPickerOpen, setRunPickerOpen] = useState(false);
  const [runPickerTarget, setRunPickerTarget] = useState('');

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
  const hasCallerContext = Boolean(callerPolicyId || callerTargetId);
  const callerBackLabel = callerPolicyId ? 'Back to schedule' : callerTargetId ? 'Back to target' : 'Check library';

  if (!entityId) {
    return (
      <div className="content">
        <DetailPageIntro route="check-detail" />
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
          <DetailPageIntro route="check-detail" />
          <DetailLoadingPlaceholder label="Loading check…" variant="layout" />
        </div>
      );
    }
    return (
      <div className="content">
        <DetailPageIntro route="check-detail" />
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
            actionLabel={hasCallerContext ? callerBackLabel : 'Open check library'}
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
  const spaced = (value: string) => value.replace(/_/g, ' ');
  const humanize = (value: string) => {
    const text = spaced(value);
    return text.charAt(0).toUpperCase() + text.slice(1);
  };
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
  const evidenceTier = getString(check, ['evidence_tier'], '').toUpperCase();
  const observationOnly = check.observation_only === true || check.readiness_conclusion === false || ['E1', 'E2'].includes(evidenceTier);
  const checkSpecificRemediation = Boolean(recordedRemediation) && recordedRemediation !== GENERIC_CHECK_REMEDIATION;
  const tailoredRemediation = execution.kind === 'Request only' || execution.kind === 'Metadata evaluation' || execution.kind === 'Operations self-check';
  const recordedObservationExplanation = getString(check, ['explanation_template'], '');
  const observationExplanation = recordedObservationExplanation && recordedObservationExplanation !== GENERIC_CHECK_EXPLANATION
    ? recordedObservationExplanation
    : 'This check records observations only. It never reports a protection gap on its own.';
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
  const scheduleHref = `#test-policies?check=${encodeURIComponent(entityId)}${callerTarget && callerCompatible ? `&target=${encodeURIComponent(callerTargetId)}` : ''}`;
  const canSchedule = customerRunnable && sessionHasPermission(session, 'test_policy:write') && (!callerTargetId || callerCompatible === true);
  const canRunRole = ['owner', 'admin', 'engineer'].includes(String(session.role ?? '')) && sessionHasPermission(session, 'test_run:start');
  const canOfferRun = customerRunnable && canRunRole;
  const runOnTargetHref = (targetId: string) => `${buildDetailHref('target-detail', targetId)}&tab=validate&check=${encodeURIComponent(entityId)}`;
  const runPickerTargets = declaredTargets.filter((item) => getString(item, ['id'], '') && !item.deleted_at && isPolicyTargetCompatible(check, item));
  const runDisabledReason = callerTargetId && callerCompatible === false
    ? `This check does not run on ${callerTarget ? targetLabel(callerTargetId) : 'this target'}; it supports ${supportedTargets.map(spaced).join(', ') || 'no declared target kind'}.`
    : !callerTargetId && runPickerTargets.length === 0
      ? `No declared target supports this check (${supportedTargets.map(spaced).join(', ') || 'no declared target kind'}).`
      : '';
  const dispatchingSchedules = linkedPolicyState.items.filter((item) => ['scheduled', 'due'].includes(describeScheduleDispatch(item, data.checks).bucket)).length;

  const policyColumns: TableColumn<DataItem>[] = [
    { key: 'schedule', label: 'Schedule', render: (item) => {
      const policyId = getString(item, ['id', 'policy_id'], '');
      const name = scheduleDisplayName(item, data.checks);
      return policyId ? <DetailEntityLink route="policy-detail" id={policyId} label={name} /> : <strong>{name}</strong>;
    } },
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
    { key: 'observed', label: 'Observed', render: (item) => {
      const runId = getString(item, ['id'], '');
      const observed = formatDate(item.completed_at ?? item.updated_at ?? item.created_at);
      return runId
        ? <a className="detail-entity-link mono" href={buildDetailHref('run-detail', runId)} aria-label={`Open run ${runId}`}>{observed}</a>
        : <span className="mono">{observed}</span>;
    } },
    { key: 'outcome', label: 'Outcome', render: (item) => {
      const notTested = requiredInputMissing(item);
      if (notTested) return <NotTestedBadge info={notTested} />;
      const outcome = hasEvidenceBackedVerdict(item, data.evidence) ? runVerdictValue(item) : '';
      return outcome
        ? <VerdictBadge value={outcome} tone={verdictTone(outcome)} />
        : <span className="muted">{['planned', 'running', 'collecting'].includes(getString(item, ['status'], '')) ? 'In progress' : 'No evidence-backed result'}</span>;
    } },
    { key: 'evidence', label: 'Evidence', render: (item) => <RunEvidenceButton run={item} /> }
  ];

  return (
    <div className="content">
      <CustomerPageStyles />
      <DetailPageHeader
        route="check-detail"
        entityId={entityId}
        title={title}
        actions={(
          <>
            {hasCallerContext ? <AnchorButton size="sm" variant="ghost" href={callerBackHref}>{callerBackLabel}</AnchorButton> : null}
            {canOfferRun ? (
              callerTargetId && callerCompatible ? (
                <AnchorButton size="sm" variant="default" href={runOnTargetHref(callerTargetId)}>Run on {targetLabel(callerTargetId)}</AnchorButton>
              ) : runDisabledReason ? (
                <Button size="sm" variant="default" disabled title={runDisabledReason} aria-describedby="check-run-disabled-reason">{callerTargetId ? `Run on ${targetLabel(callerTargetId)}` : 'Run on a target'}</Button>
              ) : !callerTargetId ? (
                <Button size="sm" variant="default" aria-expanded={runPickerOpen} aria-controls="check-run-picker" onClick={() => setRunPickerOpen((open) => !open)}>Run on a target</Button>
              ) : null
            ) : null}
            {canSchedule ? (
              <AnchorButton size="sm" variant="secondary" href={scheduleHref}>
                {callerTarget ? `Schedule on ${targetLabel(callerTargetId)}` : 'Schedule this check'}
              </AnchorButton>
            ) : null}
          </>
        )}
      />
      {canOfferRun && runDisabledReason ? <p className="muted small" id="check-run-disabled-reason">{runDisabledReason}</p> : null}
      {canOfferRun && !callerTargetId && runPickerOpen && runPickerTargets.length > 0 ? (
        <div className="form-banner neutral stack-tight" id="check-run-picker" role="group" aria-label="Choose a target to run this check on">
          <Select
            label="Compatible target"
            value={runPickerTarget}
            placeholder="Choose a target"
            onChange={setRunPickerTarget}
            options={runPickerTargets.map((item) => ({ value: getString(item, ['id'], ''), label: getString(item, ['value', 'hostname'], getString(item, ['id'], '')) }))}
          />
          <div className="row-actions">
            <AnchorButton size="sm" variant="default" href={runPickerTarget ? runOnTargetHref(runPickerTarget) : undefined} disabled={!runPickerTarget}>Open validation on this target</AnchorButton>
            <Button size="sm" variant="ghost" onClick={() => setRunPickerOpen(false)}>Cancel</Button>
          </div>
        </div>
      ) : null}
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
            ? <>This catalog entry is SOC-governed. High-scale validation is arranged with AstraNull SOC. <a href="#support">Contact support</a> to request one.</>
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
              {evidenceRequired.length === 1 && evidenceRequired[0] === 'probe_result' && probeKind
                ? `${plainCodeLabel(probeKind)} probe result (transport, response and protocol facts)`
                : evidenceRequired.length ? humanize(evidenceRequired.map(spaced).join(', ')) : 'Evidence types not recorded in the catalog.'}
            </p>
          </div>
          <div>
            <p className="check-fact-label">How it is evaluated</p>
            <p className="check-detail-text">
              {verdictLogic || explanation || 'Evaluation rule not recorded.'}
              {expectedBehavior && !observationOnly ? <> Expected behavior: <strong title={expectedBehavior}>{plainCodeLabel(expectedBehavior).toLowerCase()}</strong>.</> : null}
            </p>
            {expectedBehavior && observationOnly ? (
              <p className="muted small" title={expectedBehavior}>Reference control, not verified by this check: {plainCodeLabel(expectedBehavior).toLowerCase()}.</p>
            ) : null}
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
              <p className="check-fact-label">What it tests</p>
              <CheckClassSummary check={check} />
            </div>
            <div>
              <p className="check-fact-label">Target kinds</p>
              {supportedTargets.length ? <div className="chip-row">{supportedTargets.map((kind) => <Badge key={kind} tone="muted">{spaced(kind)}</Badge>)}</div> : <p className="muted">Not recorded</p>}
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
                  <div className="chip-row">
                    {maxEvents ? <Badge tone="muted">max {maxEvents} events</Badge> : null}
                    {maxDuration ? <Badge tone="muted">max {maxDuration} sec</Badge> : null}
                    {maxConcurrent ? <Badge tone="muted">{maxConcurrent} concurrent in the execution slot</Badge> : null}
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
                  <VerdictBadge value={runVerdictValue(latestResult)} tone={verdictTone(runVerdictValue(latestResult))} />
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

      {observationOnly ? (
        <Card>
          <CardHeader>
            <CardTitle>What this result can and cannot tell you</CardTitle>
            <CardDescription>This check is observation only: it records what the probe saw and cannot establish a protection verdict.</CardDescription>
          </CardHeader>
          <CardContent>
            <p className="check-detail-text">{observationExplanation}</p>
          </CardContent>
        </Card>
      ) : remediation && (checkSpecificRemediation || tailoredRemediation) ? (
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

      <Card>
        <CardHeader>
          <CardTitle>Schedules bound to this check</CardTitle>
          <CardDescription>
            {linkedPolicyState.status === 'loaded' && linkedPolicyState.items.length > 0
              ? `${formatNumber(dispatchingSchedules)} of ${formatNumber(linkedPolicyState.items.length)} dispatch automatically. Bound to this exact check ID.`
              : 'Schedules bound to this exact check ID.'}
          </CardDescription>
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

      <details className="detail-technical">
        <summary><ChevronRight className="detail-technical-chevron" size={16} aria-hidden="true" />Technical details</summary>
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
        <DetailPageIntro route="policy-detail" />
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
        <DetailPageIntro route="policy-detail" />
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
  const gates: Array<{ label: string; status: 'met' | 'blocked' | 'info'; detail: string; action?: ReactNode }> = [
    {
      label: 'Exact target bound',
      status: target.targetId ? 'met' : 'blocked',
      detail: target.targetId ? target.targetLabel : 'Legacy schedule without an exact target. Create a new schedule bound to one target.',
      action: !target.targetId && canWrite ? (
        <AnchorButton
          size="sm"
          variant="secondary"
          href={`#test-policies?check=${encodeURIComponent(check.checkId)}`}
          aria-label="Create replacement schedule bound to one target"
        >Create replacement</AnchorButton>
      ) : undefined
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
      status: target.targetId && state === 'active' && policy.enabled !== false ? 'met' : 'blocked',
      detail: !target.targetId
        ? 'Cannot be enabled: the schedule has no exact target. Create a replacement bound to one target.'
        : !state
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
  const declaredTargetLabels = new Map(data.targets.map((item) => [getString(item, ['id'], ''), getString(item, ['value', 'hostname'], '')]));
  const historyDispatchMs = runRelationState.items.reduce((latest, run) => {
    const ms = Math.max(Date.parse(String(run.started_at ?? '')) || 0, Date.parse(String(run.created_at ?? '')) || 0);
    return Math.max(latest, ms);
  }, 0);
  const lastDispatchedDisplay: ReactNode = lastDispatchedAt
    ? formatDate(lastDispatchedAt)
    : historyDispatchMs > 0
      ? <>{formatDate(new Date(historyDispatchMs).toISOString())} <span className="muted">from run history</span></>
      : runRelationState.status === 'loading' || runRelationState.status === 'idle'
        ? 'Checking run history…'
        : runRelationState.status === 'error'
          ? 'Not recorded'
          : 'Never dispatched';
  const runColumns: TableColumn<DataItem>[] = [
    { key: 'recorded', label: 'Dispatched', render: (run) => {
      const runId = getString(run, ['id'], '');
      const dispatched = formatDate(run.started_at ?? run.created_at);
      return runId
        ? <a className="detail-entity-link mono" href={buildDetailHref('run-detail', runId)} aria-label={`Open run ${runId}`}>{dispatched}</a>
        : <span className="mono">{dispatched}</span>;
    } },
    { key: 'target', label: 'Target', render: (run) => {
      const runTargetId = getString(run, ['target_id'], '');
      if (!runTargetId) return <span className="muted">Not recorded</span>;
      const label = declaredTargetLabels.get(runTargetId) || (runTargetId === target.targetId && target.targetLabel !== runTargetId ? target.targetLabel : '');
      return label
        ? <DetailEntityLink route="target-detail" id={runTargetId} label={label} />
        : <a className="detail-entity-link" href={buildDetailHref('target-detail', runTargetId)}><code>{runTargetId}</code></a>;
    } },
    { key: 'status', label: 'Status', render: (run) => <StatusBadge value={getString(run, ['status'], '')} tone={runStatusBadgeTone(getString(run, ['status'], ''))} fallback="Not recorded" /> },
    { key: 'outcome', label: 'Outcome', render: (run) => {
      const notTested = requiredInputMissing(run);
      if (notTested) return <NotTestedBadge info={notTested} />;
      const outcome = hasEvidenceBackedVerdict(run, data.evidence) ? runVerdictValue(run) : '';
      return outcome ? <VerdictBadge value={outcome} tone={verdictTone(outcome)} /> : <span className="muted">No evidence-backed result</span>;
    } },
    { key: 'evidence', label: 'Evidence', render: (run) => <RunEvidenceButton run={run} /> }
  ];

  return (
    <div className="content">
      <CustomerPageStyles />
      <DetailPageHeader
        route="policy-detail"
        entityId={entityId}
        title={title}
        actions={(
          <>
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
      {!canWrite ? <p className="muted small">Read only. Ask an owner or admin to change schedules.</p> : null}
      <Card className="schedule-dispatch-card">
        <CardHeader>
          <CardTitle>Will this schedule run?</CardTitle>
          <CardDescription>From the recorded schedule only. Configuration is not execution proof; gates are rechecked at dispatch.</CardDescription>
        </CardHeader>
        <CardContent className="stack-tight">
          <div className="row-actions">
            <ScheduleStateBadge dispatch={dispatch} />
            <span className="small muted">{dispatch.reason}</span>
          </div>
          <div className="kv-list schedule-dispatch-facts">
            <div><span>Next run</span><strong>{next ? <>{next.primary} <span className="muted">{next.zone}</span></> : 'No next run recorded'}</strong></div>
            {next?.viewer ? <div><span>In your timezone</span><strong>{next.viewer}</strong></div> : null}
            <div><span>Last dispatched</span><strong>{lastDispatchedDisplay}</strong></div>
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
            <div><span>Check</span>{checkHref ? <a className="detail-entity-link" href={checkHref}>{check.name}</a> : <strong>Not recorded</strong>}</div>
            <div><span>Exact target</span>{target.targetId ? <DetailEntityLink route="target-detail" id={target.targetId} label={target.targetLabel} /> : <strong className="muted">No exact target</strong>}</div>
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
            <div><span>Expected verdict</span><strong title={expected || undefined}>{expected ? plainExpectedVerdictLabel(expected) : 'Not recorded'}</strong></div>
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
          <ul className="placement-gates gates-stacked" aria-label="Schedule dispatch gates">
            {gates.map((gate) => (
              <li key={gate.label}>
                {gate.status === 'blocked' ? <TriangleAlert size={14} aria-hidden="true" /> : gate.status === 'met' ? <ShieldCheck size={14} aria-hidden="true" /> : <Info size={14} aria-hidden="true" />}
                <span className="gate-text"><span>{gate.label}</span><span className="muted small">{plainInlineText(gate.detail)}</span>{gate.action ? <span>{gate.action}</span> : null}</span>
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
        <summary><ChevronRight className="detail-technical-chevron" size={16} aria-hidden="true" />Technical record</summary>
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

  const runFallback = data.runs.find((item) => getString(item, ['id'], '') === entityId) ?? null;
  const tenantFallback = data.internalTenants.find((item) => getString(item, ['tenant_id', 'id'], '') === entityId) ?? null;
  const findingFallback = data.findings.find((item) => getString(item, ['id'], '') === entityId) ?? null;
  const highScaleFallback = data.highScale.find((item) => getString(item, ['id'], '') === entityId) ?? null;

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
  // Mutations on an entity detail page must re-read the entity itself, not just the list
  // datasets onRefresh reloads; otherwise removed targets, triage changes, etc. stay on screen.
  const activeEntityReload = route === 'run-detail'
      ? runDetail.reload
      : route === 'tenant-detail'
        ? tenantDetail.reload
        : route === 'finding-detail'
          ? findingDetailState.reload
          : route === 'queue-detail'
            ? highScaleDetail.reload
            : null;
  const refreshWithEntity = useCallback(async () => {
    await Promise.all([onRefresh(), activeEntityReload ? activeEntityReload() : Promise.resolve()]);
  }, [onRefresh, activeEntityReload]);
  const detailState =
    route === 'run-detail' ? runDetail
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
          <DetailPageIntro route={route} context="Staff-only surface" />
          <EmptyState icon={Target} title="No tenant selected." body="Open a tenant from the staff directory with ?id= or use the Detail link on #admin." actionLabel="Open staff admin" actionHref="#admin" />
        </div>
      );
    }
    if (session.principal !== 'staff') {
      return (
        <div className="content">
          <DetailPageIntro route={route} context="Staff-only surface" />
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
          <DetailPageIntro route={route} />
          <EmptyState icon={TriangleAlert} title="No finding selected." body="Open a finding from the list with ?id= or use the View link on #findings." actionLabel="Open findings" actionHref="#findings" />
        </div>
      );
    }
    const findingEntity = findingDetailState.detail ?? findingFallback;
    if (!findingEntity && findingDetailState.loading) {
      return (
        <div className="content">
          <DetailPageIntro route={route} />
          <DetailLoadingPlaceholder label="Loading finding detail…" />
        </div>
      );
    }
    if (!findingEntity) {
      return (
        <div className="content">
          <DetailPageIntro route={route} />
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
          <DetailPageIntro route={route} />
          <EmptyState icon={Target} title="No target selected." body="Open a declared target from Targets." actionLabel="Open targets" actionHref="#targets" />
        </div>
      );
    }
    return <TargetDetailView entityId={entityId} config={config} session={session} checks={data.checks} wafEdgeEnabled={data.deploymentFeatures?.waf_posture === true} protectionValidationEnabled={data.deploymentFeatures?.protection_validation === true} deploymentFeatures={data.deploymentFeatures} onRefresh={onRefresh} />;
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
          <DetailPageIntro route={route} context={staffSocWorkspace ? 'SOC execution workspace' : 'High-scale authorization pack'} />
          <EmptyState
            icon={ShieldCheck}
            title="No high-scale request selected."
            body={staffSocWorkspace
              ? 'Open a queue item from the SOC console with ?id=.'
              : 'This address does not name a high-scale request. Open the request link you received, or open a target to see its validation.'}
            actionLabel={staffSocWorkspace ? 'Open SOC console' : 'Open targets'}
            actionHref={staffSocWorkspace ? '#internal-soc' : '#targets'}
          />
        </div>
      );
    }
    const queueEntity = highScaleDetail.detail ?? highScaleFallback;
    if (!queueEntity && highScaleDetail.loading) {
      return (
        <div className="content">
          <DetailPageIntro route={route} context={staffSocWorkspace ? 'SOC execution workspace' : 'High-scale authorization pack'} />
          <DetailLoadingPlaceholder label="Loading high-scale request…" />
        </div>
      );
    }
    if (!queueEntity) {
      return (
        <div className="content">
          <DetailPageIntro route={route} context={staffSocWorkspace ? 'SOC execution workspace' : 'High-scale authorization pack'} />
          <EmptyState
            icon={ShieldCheck}
            title="High-scale request not found."
            body={highScaleDetail.error || 'The requested high-scale item is missing or outside this tenant scope.'}
            actionLabel={staffSocWorkspace ? 'Open SOC console' : 'Open targets'}
            actionHref={staffSocWorkspace ? '#internal-soc' : '#targets'}
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
          data={data}
          config={config}
          session={session}
          onRefresh={refreshWithEntity}
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
        onRefresh={refreshWithEntity}
        loading={highScaleDetail.loading}
        loadError={highScaleDetail.error}
      />
    );
  }

  if (!entityId) {
    const noSelectionByRoute: Partial<Record<RouteId, { title: string; body: string; actionLabel: string; actionHref: string; icon: typeof Target }>> = {
      'run-detail': {
        title: 'No test run selected.',
        body: 'Open a target and select a check to see its runs.',
        actionLabel: 'Open targets',
        actionHref: '#targets',
        icon: Activity
      },
      'finding-detail': {
        title: 'No finding selected.',
        body: 'Open a finding from the list with ?id= or use the View link on #findings.',
        actionLabel: 'Open findings',
        actionHref: '#findings',
        icon: TriangleAlert
      },
      'queue-detail': {
        title: 'No SOC request selected.',
        body: 'Open a queue item from Test runs or the SOC console with ?id=.',
        actionLabel: 'Open SOC console',
        actionHref: '#internal-soc',
        icon: ShieldCheck
      },
      'target-detail': {
        title: 'No target selected.',
        body: 'Open a declared target from Targets.',
        actionLabel: 'Open targets',
        actionHref: '#targets',
        icon: Target
      }
    };
    const noSelection = noSelectionByRoute[route];
    return (
      <div className="content">
        <DetailPageIntro route={route} />
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
        <DetailPageIntro route={route} />
        <DetailLoadingPlaceholder label="Loading entity detail…" />
      </div>
    );
  }

  if (!entity) {
    const listHrefByRoute: Partial<Record<RouteId, { actionLabel: string; actionHref: string }>> = {
      'run-detail': { actionLabel: 'Open targets', actionHref: '#targets' },
    };
    const listLink = listHrefByRoute[route];
    return (
      <div className="content">
        <DetailPageIntro route={route} />
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
      <DetailPageIntro route={route} />
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

const LIVE_FINDING_READ_LIMIT = 100;
const LIVE_FINDING_CONCURRENCY = 4;

type LiveFindingRead = { status: 'loading' | 'ready' | 'error'; finding: DataItem | null };

/** Current lifecycle of each finding the report captured: one exact read per captured finding ID, never the loaded page. */
function ReportLiveFindingStatus({
  data,
  config,
  session,
  snapshotFindings,
  hasSnapshot,
  targets,
  checkedAt
}: {
  data: PortalData;
  config: PortalConfig;
  session: Session;
  snapshotFindings: DataItem[];
  hasSnapshot: boolean;
  targets: DataItem[];
  checkedAt: string;
}) {
  const readable = canReadDataset(session, 'findings');
  const findingIds = useMemo(
    () => [...new Set(snapshotFindings.map((item) => getString(item, ['id'], '')).filter(Boolean))].slice(0, LIVE_FINDING_READ_LIMIT),
    [snapshotFindings]
  );
  const idsKey = findingIds.join('|');
  const [reads, setReads] = useState<Record<string, LiveFindingRead>>({});
  const [reloadTick, setReloadTick] = useState(0);

  useEffect(() => {
    if (!readable || findingIds.length === 0) {
      setReads({});
      return undefined;
    }
    let cancelled = false;
    setReads(Object.fromEntries(findingIds.map((id) => [id, { status: 'loading', finding: null }])));
    let cursor = 0;
    const worker = async () => {
      while (!cancelled && cursor < findingIds.length) {
        const id = findingIds[cursor];
        cursor += 1;
        try {
          const payload = await requestJson(config, session, `/v1/findings/${encodeURIComponent(id)}`);
          const finding = payload && typeof payload === 'object' && !Array.isArray(payload) ? payload as DataItem : null;
          if (!cancelled) setReads((current) => ({ ...current, [id]: { status: finding ? 'ready' : 'error', finding } }));
        } catch {
          if (!cancelled) setReads((current) => ({ ...current, [id]: { status: 'error', finding: null } }));
        }
      }
    };
    void Promise.all(Array.from({ length: Math.min(LIVE_FINDING_CONCURRENCY, findingIds.length) }, worker));
    return () => { cancelled = true; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [config, session, idsKey, readable, reloadTick]);

  const snapshotById = new Map(snapshotFindings.map((item) => [getString(item, ['id'], ''), item]));
  const rows = findingIds.map((id) => ({ id, snapshot: snapshotById.get(id) ?? {}, read: reads[id] ?? { status: 'loading', finding: null } as LiveFindingRead }));
  const settled = rows.filter((row) => row.read.status !== 'loading');
  const ready = rows.filter((row) => row.read.status === 'ready' && row.read.finding);
  const failed = rows.filter((row) => row.read.status === 'error').length;
  const stillOpen = ready.filter((row) => findingStatus(row.read.finding as DataItem) === 'open').length;
  const changed = ready.filter((row) => findingStatus(row.read.finding as DataItem) !== getString(row.snapshot, ['status'], '')).length;
  const capped = snapshotFindings.length > LIVE_FINDING_READ_LIMIT;

  const columns: TableColumn<{ id: string; snapshot: DataItem; read: LiveFindingRead }>[] = [
    { key: 'finding', label: 'Finding', render: (row) => (
      <span className="cp-stack">
        <DetailEntityLink route="finding-detail" id={row.id} label={plainFindingTitle(row.read.finding ?? row.snapshot, targets, data.checks)} />
        <span className="mono muted small">{row.id}</span>
      </span>
    ) },
    { key: 'then', label: 'Status at generation', render: (row) => {
      const status = getString(row.snapshot, ['status'], '');
      return status ? <StatusBadge value={status} tone={findingStatusTone(status)} /> : <span className="muted">Not recorded</span>;
    } },
    { key: 'now', label: 'Status now', render: (row) => {
      if (row.read.status === 'loading') return <span className="muted">Reading…</span>;
      if (row.read.status === 'error' || !row.read.finding) return <span className="muted">Not available</span>;
      const status = findingStatus(row.read.finding);
      return <StatusBadge value={status} tone={findingStatusTone(status)} />;
    } },
    { key: 'changed', label: 'Changed', render: (row) => {
      if (row.read.status !== 'ready' || !row.read.finding) return <span className="muted">—</span>;
      const moved = findingStatus(row.read.finding) !== getString(row.snapshot, ['status'], '');
      return <Badge tone={moved ? 'warn' : 'muted'}>{moved ? 'Changed' : 'Unchanged'}</Badge>;
    } }
  ];

  return (
    <Card>
      <CardHeader>
        <CardTitle>Captured findings: status now</CardTitle>
        <CardDescription>Checked {formatTimestamp(checkedAt)} by reading each finding this report captured. Use it for remediation follow-up; it does not rewrite the report.</CardDescription>
      </CardHeader>
      <CardContent className="stack-tight">
        {!readable ? (
          <p className="muted">Your role cannot read findings, so current status is not shown.</p>
        ) : !hasSnapshot ? (
          <p className="muted">Not recorded (legacy report).</p>
        ) : findingIds.length === 0 ? (
          <p className="muted">This report captured no findings.</p>
        ) : (
          <>
            <p className="muted small" role="status">
              {settled.length < rows.length
                ? `Reading ${formatNumber(rows.length)} captured ${pluralize(rows.length, 'finding')}…`
                : `${formatNumber(stillOpen)} of ${formatNumber(rows.length)} captured findings are still open; ${formatNumber(changed)} changed since generation.`}
              {failed > 0 ? ` ${formatNumber(failed)} could not be read.` : ''}
              {capped ? ` Only the first ${formatNumber(LIVE_FINDING_READ_LIMIT)} captured findings are checked.` : ''}
            </p>
            {failed > 0 && settled.length === rows.length ? (
              <div className="row-actions"><Button size="sm" variant="secondary" onClick={() => setReloadTick((count) => count + 1)}>Retry</Button></div>
            ) : null}
            <DataTable columns={columns} items={rows} getRowId={(row) => row.id} empty={null} />
          </>
        )}
      </CardContent>
    </Card>
  );
}

function ReportComparisonCard({
  report,
  reports,
  config,
  session,
  targets,
  checks
}: {
  report: DataItem;
  reports: DataItem[];
  config: PortalConfig;
  session: Session;
  targets: DataItem[];
  checks: DataItem[];
}) {
  const candidates = useMemo(() => eligibleBaselines(report, reports), [report, reports]);
  const [chosenId, setChosenId] = useState('');
  const selectedId = chosenId && candidates.some((item) => getString(item, ['id'], '') === chosenId)
    ? chosenId
    : getString(candidates[0] ?? {}, ['id'], '');
  const [baseline, setBaseline] = useState<{ id: string; status: 'idle' | 'loading' | 'loaded' | 'error'; report: DataItem | null; error: string }>({ id: '', status: 'idle', report: null, error: '' });
  const [reloadTick, setReloadTick] = useState(0);

  useEffect(() => {
    if (!selectedId) {
      setBaseline({ id: '', status: 'idle', report: null, error: '' });
      return undefined;
    }
    let cancelled = false;
    setBaseline({ id: selectedId, status: 'loading', report: null, error: '' });
    requestJson(config, session, `/v1/reports/${encodeURIComponent(selectedId)}`)
      .then((payload) => {
        if (cancelled) return;
        const stored = payload && typeof payload === 'object' && !Array.isArray(payload) ? payload as DataItem : null;
        setBaseline(stored ? { id: selectedId, status: 'loaded', report: stored, error: '' } : { id: selectedId, status: 'error', report: null, error: 'The baseline report response was not a report record.' });
      })
      .catch((err) => {
        if (!cancelled) setBaseline({ id: selectedId, status: 'error', report: null, error: apiErrorMessage(err, 'The baseline report could not be loaded.') });
      });
    return () => { cancelled = true; };
  }, [selectedId, config, session, reloadTick]);

  const diff = !selectedId
    ? diffReports(report, null)
    : baseline.id === selectedId && baseline.status === 'loaded'
      ? diffReports(report, baseline.report)
      : null;
  const findingLink = (item: { id: string; title: string }) => (
    <DetailEntityLink route="finding-detail" id={item.id} label={plainFindingTitle(item, targets, checks)} />
  );
  const changeList = (label: string, items: Array<{ id: string; title: string; detail?: string }>) => (
    items.length ? (
      <div key={label}>
        <p className="check-fact-label">{label} ({formatNumber(items.length)})</p>
        <ul className="report-live-list">
          {items.slice(0, 10).map((item) => (
            <li key={item.id}>{findingLink(item)}{item.detail ? <span className="muted small"> · {item.detail}</span> : null}</li>
          ))}
        </ul>
        {items.length > 10 ? <p className="muted small">and {formatNumber(items.length - 10)} more.</p> : null}
      </div>
    ) : null
  );

  return (
    <Card>
      <CardHeader>
        <CardTitle>Compared with previous report</CardTitle>
        <CardDescription>Derived from two stored snapshots: this report and an earlier report of the same kind and scope. Nothing is filled in from current data.</CardDescription>
      </CardHeader>
      <CardContent className="stack-tight">
        {candidates.length > 1 ? (
          <Select
            label="Baseline report"
            value={selectedId}
            onChange={setChosenId}
            options={candidates.map((item) => ({
              value: getString(item, ['id'], ''),
              label: `${getString(item, ['title'], getString(item, ['id'], 'Report'))} · ${formatTimestamp(reportAsOf(item))}`
            }))}
          />
        ) : candidates.length === 1 ? (
          <p className="muted small">Baseline: <DetailEntityLink route="report-detail" id={selectedId} label={getString(candidates[0], ['title'], selectedId)} /> · {formatTimestamp(reportAsOf(candidates[0]))}</p>
        ) : null}
        {selectedId && baseline.id === selectedId && baseline.status === 'error' ? (
          <div className="form-banner error row-actions" role="alert">
            <span>Not compared: {baseline.error}</span>
            <Button size="sm" variant="secondary" onClick={() => setReloadTick((count) => count + 1)}>Retry</Button>
          </div>
        ) : !diff ? (
          <p className="muted small" role="status">Reading the baseline report…</p>
        ) : diff.status === 'not_compared' ? (
          <p className="muted">Not compared: {diff.reason}</p>
        ) : (
          <>
            <div className="kv-list">
              <div><span>New findings</span><strong>{formatNumber(diff.added.length)}</strong></div>
              <div><span>No longer present</span><strong>{formatNumber(diff.removed.length)}</strong></div>
              <div><span>Status changed</span><strong>{formatNumber(diff.statusChanged.length)}{diff.statusChanged.some((item) => item.acceptedRisk) ? ` (${formatNumber(diff.statusChanged.filter((item) => item.acceptedRisk).length)} newly accepted risk)` : ''}</strong></div>
              <div><span>Severity changed</span><strong>{formatNumber(diff.severityChanged.length)}</strong></div>
              <div><span>Unchanged</span><strong>{formatNumber(diff.unchanged)}</strong></div>
              <div>
                <span>Readiness score</span>
                <strong>{diff.readiness.compared
                  ? `${formatNumber(diff.readiness.from)} → ${formatNumber(diff.readiness.to)} (${diff.readiness.delta > 0 ? '+' : ''}${formatNumber(diff.readiness.delta)})`
                  : `Not compared: ${diff.readiness.reason}`}</strong>
              </div>
            </div>
            {changeList('New findings', diff.added)}
            {changeList('No longer present', diff.removed)}
            {changeList('Status changed', diff.statusChanged.map((item) => ({ ...item, detail: `${formatStatusLabel(item.from, 'Not recorded')} → ${formatStatusLabel(item.to, 'Not recorded')}` })))}
            {changeList('Severity changed', diff.severityChanged.map((item) => ({ ...item, detail: `${formatSeverityLabel(item.from)} → ${formatSeverityLabel(item.to)}` })))}
            {diff.readiness.compared && diff.readiness.factors.length ? (
              <div>
                <p className="check-fact-label">Score factors that moved</p>
                <ul className="report-live-list">
                  {diff.readiness.factors.map((factor) => (
                    <li key={factor.key}>{formatStatusLabel(factor.label)}: {factor.from ?? 'not recorded'} → {factor.to ?? 'not recorded'}</li>
                  ))}
                </ul>
              </div>
            ) : null}
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
  const declaredTargets = useDeclaredTargets(data, config, session);

  if (!entityId) {
    return (
      <div className="content">
        <DetailPageIntro route="report-detail" />
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
        <DetailPageIntro route="report-detail" />
        <DetailLoadingPlaceholder label="Loading report…" variant="layout" />
      </div>
    );
  }

  if (!report) {
    const denied = /forbidden|permission|403/i.test(reportDetail.error);
    return (
      <div className="content">
        <DetailPageIntro route="report-detail" />
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
  const openedInPeriod = getNestedNumber(report, ['summary', 'findings_snapshot', 'opened_in_period'], NaN);
  const excludedByPeriod = getNestedNumber(report, ['summary', 'findings_snapshot', 'excluded_by_period'], 0);
  const readinessFactors = getNestedArray(report, ['summary', 'readiness_factors']);
  const scoreBasisMissing = hasReadinessScore && (!frozen || readinessFactors.length === 0);
  const frameworkKind = reportKindIsFramework(kind);
  const targetLabels = new Map(declaredTargets.map((item) => [getString(item, ['id'], ''), getString(item, ['value', 'hostname'], '')]));
  const compliance = getNestedItem(report, ['summary', 'compliance']);
  const frameworks = Array.isArray(compliance?.frameworks) ? (compliance!.frameworks as unknown[]).map(String) : [];
  const scope = getNestedItem(summary, ['scope']);
  const scopeMode = getString(scope ?? {}, ['mode'], '');
  const periodBounds = getNestedItem(scope, ['period']);
  const declaredMembers = getNestedItem(scope, ['declared_members']);
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
      : scopeMode === 'target_groups'
        ? 'Historical domain scope (exact domain IDs not captured)'
      : [
        scopeTargetIds.length ? `${formatNumber(scopeTargetIds.length)} selected target${scopeTargetIds.length === 1 ? '' : 's'}` : '',
        scopeMode === 'runs' ? 'Explicit runs' : ''
      ].filter(Boolean).join(' · ') || scopeMode.replaceAll('_', ' ');
  const periodText = periodBounds
    ? getString(periodBounds, ['status'], '') === 'bounded'
      ? `${formatTimestamp(getString(periodBounds, ['start'], ''))} to ${formatTimestamp(getString(periodBounds, ['end'], ''))}`
      : getString(periodBounds, ['status'], '') === 'unbounded' ? `All time, until ${formatTimestamp(getString(periodBounds, ['end'], ''))}` : 'Not recorded'
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
      return targetId ? <DetailEntityLink route="target-detail" id={targetId} label={targetLabels.get(targetId) || targetId} /> : <span className="muted">Not recorded</span>;
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
    { key: 'title', label: 'Finding at generation', render: (item) => (
      <span className="cp-stack">
        <DetailEntityLink route="finding-detail" id={getString(item, ['id'], '')} label={plainFindingTitle(item, declaredTargets, data.checks)} />
        <span className="mono muted small">{getString(item, ['id'])}</span>
      </span>
    ) },
    { key: 'severity', label: 'Severity', render: (item) => {
      const severity = getString(item, ['severity'], '');
      return severity ? <Badge tone={severityTone(severity)}>{formatSeverityLabel(severity)}</Badge> : <span className="muted">Not recorded</span>;
    } },
    { key: 'status', label: 'Status at generation', render: (item) => {
      const status = getString(item, ['status'], '');
      return status ? <StatusBadge value={status} tone={findingStatusTone(status)} /> : <span className="muted">Not recorded</span>;
    } },
    { key: 'proof', label: 'Proof', render: (item) => <Button size="sm" variant="ghost" onClick={() => openEvidenceInspector({ entry: 'finding', finding_id: getString(item, ['id']) }, { focusKey: getString(item, ['id']) })}>View evidence</Button> }
  ];
  const formatOptions = reportOptionsFromCapabilities(data.reportCapabilities, 'formats', REPORT_FORMAT_FALLBACK_OPTIONS);
  const evidenceReferenceList = capturedEvidenceIds.length === 0
    ? <p className="muted">{summary ? 'No evidence references were captured.' : 'Not recorded (legacy report).'}</p>
    : (
      <ul className="report-live-list">
        {capturedEvidenceIds.map((evidenceId) => {
          const known = evidenceItems.find((item) => getString(item, ['id'], '') === evidenceId);
          const knownLabel = known ? getString(known, ['label'], '') : '';
          return (
            <li key={evidenceId} className="row-actions">
              <span className="cp-stack">
                <span>{knownLabel ? humanizeSignalType(knownLabel) : 'Evidence record'}</span>
                <code className="mono-hash muted small">{evidenceId}</code>
              </span>
              <Button size="sm" variant="ghost" onClick={() => openEvidenceInspector({ entry: 'artifact', evidence_id: evidenceId }, { focusKey: evidenceId })}>View evidence</Button>
            </li>
          );
        })}
      </ul>
    );

  return (
    <div className="content report-detail-page">
      <CustomerPageStyles />
      <DetailPageHeader
        route="report-detail"
        context={reportKindIsFramework(kind) ? `${reportKindLabel(kind)} mapping` : `${reportKindLabel(kind)} report`}
        entityId={entityId}
        title={reportTitle}
        actions={(
          <>
            <Button size="sm" variant="secondary" onClick={() => openEvidenceInspector({ entry: 'report', report_id: entityId })}>View snapshot evidence</Button>
            <ReportExportMenu reportId={entityId} title={reportTitle} formats={formatOptions} exporter={exporter} />
          </>
        )}
      />
      <PageContextSummary>
        {asOf ? `Snapshot frozen ${formatTimestamp(asOf)}` : `Report created ${formatTimestamp(report.created_at)} · snapshot time not recorded`} · Scope: {scopeText}
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
              <div>
                <span>Findings in this snapshot</span>
                <strong>
                  {findingsSnapshot ? countText(findingsSnapshot) : 'Not recorded'}
                  {findingsSnapshot && excludedByPeriod > 0 ? <span className="muted"> ({formatNumber(excludedByPeriod)} older closed {pluralize(excludedByPeriod, 'finding')} outside the period)</span> : null}
                </strong>
              </div>
              <div><span>Open at generation (any opened date)</span><strong>{hasOpenFindings ? formatNumber(openFindings) : 'Not recorded'}</strong></div>
              <div><span>Opened in period</span><strong>{Number.isFinite(openedInPeriod) ? formatNumber(openedInPeriod) : 'Not recorded'}</strong></div>
            </CardContent>
          </Card>
          <Card>
            <CardHeader>
              <CardTitle>Readiness at {asOf ? formatTimestamp(asOf) : 'generation'}</CardTitle>
              <CardDescription>Values recorded in the report. They do not change when current results change.</CardDescription>
            </CardHeader>
            <CardContent className="report-summary-layout">
              {hasReadinessScore ? (
                <div className="stack-tight">
                  <ReadinessGauge score={readinessScore} showBand={false} muted={scoreBasisMissing} />
                  {scoreBasisMissing ? <p className="cp-note">Score basis not recorded in this snapshot; it cannot be traced to evidence.</p> : null}
                </div>
              ) : <p className="cp-note">{readinessNote}</p>}
              <div className="kv-list">
                <div><span>{frameworkKind ? 'Framework mapping' : 'Audience'}</span><strong>{compliance ? getString(compliance, ['template_title'], reportKindLabel(kind)) : reportKindLabel(kind)}</strong></div>
                {frameworks.length ? <div><span>{frameworkKind ? 'Frameworks' : 'Control areas'}</span><strong>{frameworks.map((framework) => plainCodeLabel(framework)).join(', ')}</strong></div> : null}
                <div><span>Status</span><StatusBadge value={getString(report, ['status'], '')} tone={reportStatusTone(getString(report, ['status'], ''))} fallback="Not recorded" /></div>
              </div>
            </CardContent>
          </Card>
        </div>
        <p className="cp-note">{getString(compliance ?? {}, ['disclaimer'], 'Evidence mapping is not a certification or a statement of compliance.')} Protection profiles are {getNestedString(summary, ['sections', 'protection_profile', 'status'], 'not_included') === 'included' ? 'included' : 'not included in this report'}.</p>
        {hasReadinessScore ? (
          <Card>
            <CardHeader>
              <CardTitle>Score factors in this snapshot</CardTitle>
              <CardDescription>As recorded; not recalculated from current data.</CardDescription>
            </CardHeader>
            <CardContent>
              <DataTable
                columns={factorColumns}
                items={readinessFactors}
                getRowId={(factor) => getString(factor, ['key', 'label'], JSON.stringify(factor))}
                empty={<EmptyState icon={ClipboardList} title="No score factors recorded." body="No score factors were recorded in this snapshot." />}
              />
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
        <ReportComparisonCard report={report} reports={data.reports} config={config} session={session} targets={declaredTargets} checks={data.checks} />
        {frameworkKind ? (
          <Card>
            <CardHeader>
              <CardTitle>Evidence references ({formatNumber(capturedEvidenceIds.length)})</CardTitle>
              <CardDescription>Every evidence ID the snapshot references. Opening one shows its recorded integrity; a reference is not verification.</CardDescription>
            </CardHeader>
            <CardContent>{evidenceReferenceList}</CardContent>
          </Card>
        ) : (
          <Card>
            <CardContent>
              <details className="detail-technical" style={{ borderTop: 'none', paddingTop: 0 }}>
                <summary><ChevronRight className="detail-technical-chevron" size={16} aria-hidden="true" />Evidence references ({formatNumber(capturedEvidenceIds.length)})</summary>
                <div className="stack-tight">
                  <p className="muted small">Every evidence ID the snapshot references. Opening one shows its recorded integrity; a reference is not verification.</p>
                  {evidenceReferenceList}
                </div>
              </details>
            </CardContent>
          </Card>
        )}
        {declarationSnapshot ? (
          <p className="muted small">Declarations: {getString(declarationSnapshot, ['status'], 'not recorded').replaceAll('_', ' ')}{getNestedArray(declarationSnapshot, ['items']).length ? ` · ${formatNumber(getNestedArray(declarationSnapshot, ['items']).length)} target declarations frozen` : ''}.</p>
        ) : null}
      </section>

      <section className="report-live" aria-labelledby="report-live-heading">
        <h2 id="report-live-heading" className="report-section-title">Current status <span className="muted">· live, not part of the report</span></h2>
        <ReportLiveFindingStatus
          data={data}
          config={config}
          session={session}
          snapshotFindings={snapshotFindings}
          hasSnapshot={Boolean(findingsSnapshot)}
          targets={declaredTargets}
          checkedAt={liveCheckedAt}
        />
      </section>
    </div>
  );
}
