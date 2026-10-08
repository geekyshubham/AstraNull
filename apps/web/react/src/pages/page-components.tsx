import { Fragment, useEffect, useRef, useState, type ComponentPropsWithoutRef, type CSSProperties, type FormEvent, type HTMLAttributes, type KeyboardEvent as ReactKeyboardEvent, type MouseEvent as ReactMouseEvent, type ReactNode } from 'react';
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
  Search,
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
} from '../lib/policy-targets';
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
import { Toast } from '../components/ui/toast';
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
import { buildDetailHref, replaceRouteParams } from '../lib/route-params';
import { DEFENSIVE_RULES, NAV_GROUP_LABELS, ROUTE_BY_ID } from '../lib/navigation';
import { routeTabs } from '../lib/prototype-manifest';
import { isValidTimezone, PoliciesRefined, type PoliciesRefinedProps } from './refined/policies-refined';
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

function formatPolicyVerdictLabel(verdict: string) {
  return POLICY_VERDICT_OPTIONS.find((option) => option.value === verdict)?.label ?? verdict.replace(/_/g, ' ');
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
      // A focused link or button inside the row keeps its own activation.
      if (event.target !== event.currentTarget) return;
      event.preventDefault();
      navigate();
    }
  };
}

/**
 * Token-only styles for current-release customer pages that have no page stylesheet of their own.
 * Injected like the Plan & usage styles so they follow the shared sheet in the cascade.
 */
const CUSTOMER_PAGE_STYLES = `
.field-error { display: block; margin-top: var(--space-1); color: var(--danger); font-size: var(--text-xs); line-height: 1.4; }
.cp-stack { display: flex; min-width: 0; flex-direction: column; gap: var(--space-1); }
.cp-toolbar { display: flex; flex-wrap: wrap; align-items: center; gap: var(--space-2) var(--space-4); min-width: 0; }
.cp-toolbar > .muted { margin-left: auto; }
.cp-link { color: var(--fg); text-decoration: underline; text-decoration-color: var(--border-strong); text-underline-offset: 3px; overflow-wrap: anywhere; }
.cp-link:hover { text-decoration-color: currentColor; }
.cp-mono-wrap { font-family: var(--font-mono); font-size: var(--text-xs); overflow-wrap: anywhere; word-break: break-all; }
.cp-note { margin: 0; color: var(--fg-2); font-size: var(--text-sm); line-height: 1.5; max-width: 72ch; }
.tg-name-cell, .tg-latest, .tg-declared, .tg-coverage { display: flex; min-width: 0; flex-direction: column; gap: var(--space-1); }
.tg-name-cell { width: max-content; min-width: 18ch; max-width: 34ch; }
.tg-latest { min-width: 22ch; max-width: 30ch; }
.tg-declared { min-width: 16ch; }
.tg-name-link { color: var(--fg); font-weight: 600; text-decoration: none; overflow-wrap: anywhere; }
.tg-name-link:hover { text-decoration: underline; text-underline-offset: 3px; }
.tg-description { overflow-wrap: anywhere; }
.tg-name-link { white-space: normal; }
.tg-latest .badge { align-self: flex-start; }
.tg-open-link { display: inline-flex; min-width: 44px; min-height: 44px; align-items: center; color: var(--fg); font-weight: 600; text-decoration: underline; text-decoration-color: var(--border-strong, currentColor); text-underline-offset: 3px; }
.tg-open-link:hover { text-decoration-color: currentColor; }
.tg-open-link:focus-visible { outline: 2px solid var(--focus-color); outline-offset: 2px; border-radius: var(--radius-sm); }
.tg-count-note { max-width: 75ch; margin: 0 0 var(--space-2); }
.tg-toolbar { display: flex; flex-wrap: wrap; align-items: center; gap: var(--space-2) var(--space-4); }
.tg-toolbar > .muted { margin-left: auto; }
details.detail-technical { min-width: 0; padding: var(--space-4) 0 0; border-top: 1px solid var(--border-soft); }
details.detail-technical > summary { min-height: 44px; display: flex; align-items: center; color: var(--fg); font-weight: 600; cursor: pointer; }
details.detail-technical > summary:focus-visible { outline: 2px solid var(--focus-color); outline-offset: 2px; border-radius: var(--radius-sm); }
details.detail-technical[open] > summary { margin-bottom: var(--space-4); }
.check-explainer { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: var(--space-4) var(--space-6); }
.check-explainer > .full { grid-column: 1 / -1; }
.check-caller-context { display: flex; flex-wrap: wrap; gap: var(--space-1); }
.check-caller-context a { color: inherit; text-decoration: underline; text-underline-offset: 2px; }
.report-export-menu { position: relative; display: inline-flex; }
.report-export-options {
  position: absolute;
  top: calc(100% + var(--space-2));
  right: 0;
  z-index: var(--z-dropdown);
  display: flex;
  width: min(320px, calc(100vw - 32px));
  flex-direction: column;
  margin: 0;
  padding: var(--space-1);
  border: 1px solid var(--border-strong);
  border-radius: var(--radius-md);
  background: var(--surface);
  list-style: none;
}
.report-export-options button {
  display: flex;
  width: 100%;
  min-height: 44px;
  flex-direction: column;
  align-items: flex-start;
  gap: 2px;
  padding: var(--space-2) var(--space-3);
  border: 0;
  border-radius: var(--radius-sm);
  background: transparent;
  color: var(--fg);
  font: inherit;
  text-align: left;
  cursor: pointer;
  transition: background-color var(--motion-fast) var(--ease-standard);
}
.report-export-options button:hover { background: color-mix(in oklab, var(--accent), transparent 90%); }
.report-export-options button:focus-visible { outline: 2px solid var(--focus-color); outline-offset: -2px; }
.report-export-options small { color: var(--fg-2); font-size: var(--text-xs); }
.report-kind-group { min-width: 0; margin: 0; padding: 0; border: 0; }
.report-kind-group legend { margin-bottom: var(--space-2); padding: 0; color: var(--fg); font-weight: 600; }
.report-kind-options { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: var(--space-2); }
.report-kind-option {
  display: flex;
  min-height: 44px;
  align-items: flex-start;
  gap: var(--space-3);
  padding: var(--space-3);
  border: 1px solid var(--border);
  border-radius: var(--radius-md);
  cursor: pointer;
  transition: border-color var(--motion-fast) var(--ease-standard);
}
.report-kind-option:hover { border-color: var(--border-strong); }
.report-kind-option:has(input:checked) { border-color: var(--accent); }
.report-kind-option:has(input:focus-visible) { box-shadow: var(--focus-ring); }
.report-kind-option input { margin-top: 3px; accent-color: var(--accent); }
.report-kind-option span { display: flex; min-width: 0; flex-direction: column; gap: 2px; }
.report-kind-option small { color: var(--fg-2); font-size: var(--text-xs); line-height: 1.4; }
.report-review { display: flex; flex-direction: column; gap: var(--space-3); padding: var(--space-4); border: 1px solid var(--border); border-radius: var(--radius-md); }
.report-review h3 { margin: 0; font-size: var(--text-base); }
.report-review h3:focus { outline: none; }
.report-review h3:focus-visible { outline: 2px solid var(--focus-color); outline-offset: 2px; }
.report-review dl { margin: 0; }
.report-review dl > div { display: grid; grid-template-columns: minmax(140px, 220px) minmax(0, 1fr); gap: var(--space-3); padding: var(--space-2) 0; border-top: 1px solid var(--border-soft); }
.report-review dt { color: var(--fg-2); font-size: var(--text-sm); }
.report-review dd { margin: 0; min-width: 0; overflow-wrap: anywhere; }
.support-event-list { display: flex; flex-direction: column; margin: 0; padding: 0; list-style: none; }
.support-event-row { display: flex; flex-wrap: wrap; align-items: center; justify-content: space-between; gap: var(--space-2) var(--space-4); padding: var(--space-2) 0; border-top: 1px solid var(--border-soft); }
.support-event-row:first-child { border-top: 0; }
.support-event-row .check-row { min-width: 0; flex: 1 1 280px; }
.support-summary-preview { max-height: 280px; white-space: pre-wrap; overflow-wrap: anywhere; }
.release-dimensions { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); margin: 0; border-top: 1px solid var(--border); border-bottom: 1px solid var(--border); }
.release-dimensions > div { display: flex; min-width: 0; flex-direction: column; gap: var(--space-1); padding: var(--space-4) var(--space-5); }
.release-dimensions > div + div { border-left: 1px solid var(--border-soft); }
.release-dimensions > div:first-child { padding-left: 0; }
.release-dimensions dt { color: var(--meta); font-family: var(--font-mono); font-size: var(--text-xs); font-weight: 600; letter-spacing: var(--tracking-caps); text-transform: uppercase; }
.release-dimensions dd { margin: 0; color: var(--fg); font-family: var(--font-display); font-size: var(--text-lg); font-weight: 600; overflow-wrap: anywhere; }
.release-dimensions dd.release-dimension-hint { margin: 0; color: var(--fg-2); font-family: var(--font-body); font-size: var(--text-xs); font-weight: 400; line-height: 1.45; }
.release-evidence-page .audit-search-pill, .audit-page .audit-search-pill { flex: 0 1 auto; width: min(100%, 520px); }
.release-ledger { display: grid; grid-template-columns: minmax(0, 1fr); gap: var(--space-4); align-items: start; }
.release-filter button { min-height: 36px; }
@media (min-width: 1180px) {
  .release-ledger.has-selection { grid-template-columns: minmax(0, 7fr) minmax(0, 5fr); }
  .release-record-detail { position: sticky; top: calc(64px + var(--space-4)); }
}
@media (max-width: 900px) {
  .release-dimensions { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .release-dimensions > div:nth-child(3) { padding-left: 0; border-left: 0; }
  .release-dimensions > div:nth-child(n + 3) { border-top: 1px solid var(--border-soft); }
}
@media (max-width: 480px) {
  .release-dimensions { grid-template-columns: minmax(0, 1fr); }
  .release-dimensions > div, .release-dimensions > div + div { padding-left: 0; border-left: 0; }
  .release-dimensions > div + div { border-top: 1px solid var(--border-soft); }
}
.settings-retention-review { margin: 0; padding-left: var(--space-5); display: flex; flex-direction: column; gap: var(--space-1); }
.settings-session > summary { padding: 0 var(--space-6); }
.report-scope-options { display: grid; grid-template-columns: repeat(auto-fill, minmax(240px, 1fr)); gap: var(--space-1) var(--space-4); max-height: 320px; margin: 0; padding: var(--space-2); overflow: auto; border: 1px solid var(--border-soft); border-radius: var(--radius-md); list-style: none; }
.report-scope-options li { min-width: 0; overflow-wrap: anywhere; }
.report-generated-preview .card-header .row-actions { flex-wrap: wrap; }
.report-section-title { margin: var(--space-2) 0 0; font-size: var(--text-lg); }
.report-section-title .muted { font-family: var(--font-body); font-size: var(--text-sm); font-weight: 400; }
.audit-page .audit-filter-fields { display: grid; grid-template-columns: repeat(auto-fit, minmax(170px, 1fr)); width: 100%; }
.audit-page .audit-filter-fields .field { display: flex; min-width: 0; flex-direction: column; gap: var(--space-2); }
.audit-page .audit-filter-fields input[type="date"] { min-height: 44px; padding: 0 var(--space-3); border: 1px solid var(--border); border-radius: var(--radius-sm); background: var(--surface-sunk); color: var(--fg); font: inherit; font-size: var(--text-sm); color-scheme: dark; }
:root[data-theme="light"] .audit-page .audit-filter-fields input[type="date"] { color-scheme: light; }
.audit-page .audit-filter-fields input[type="date"]:focus-visible { outline: none; border-color: var(--focus-color); box-shadow: var(--focus-ring); }
.audit-page .audit-filter-toolbar > .cp-toolbar { width: 100%; }
.audit-event-detail:focus { outline: none; }
body .settings-page .tab-panel[hidden] { display: none; }
@media (pointer: coarse) {
  .reports-page td a, .support-page .support-event-row a, .audit-page td a, .report-detail-page td a {
    display: inline-flex; align-items: center; min-height: 44px;
  }
}
.report-snapshot-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: var(--space-4); align-items: start; }
@media (max-width: 900px) { .report-snapshot-grid { grid-template-columns: minmax(0, 1fr); } }
@media (max-width: 560px) { .report-generated-preview .kv-list > div, .report-snapshot .kv-list > div { flex-direction: column; align-items: flex-start; gap: var(--space-1); } .report-generated-preview .kv-list strong, .report-snapshot .kv-list strong { text-align: left; } }
.report-snapshot, .report-live { display: flex; min-width: 0; flex-direction: column; gap: var(--space-4); }
.report-live-list { display: flex; flex-direction: column; gap: var(--space-2); margin: 0; padding: 0; list-style: none; }
@media (max-width: 620px) {
  .report-review dl > div { grid-template-columns: minmax(0, 1fr); gap: var(--space-1); }
  .report-export-options { right: auto; left: 0; }
}
@media (prefers-reduced-motion: reduce) {
  .report-export-options button, .report-kind-option { transition: none; }
}
@media (max-width: 900px) {
  .check-explainer { grid-template-columns: minmax(0, 1fr); }
}
`;

export function CustomerPageStyles() {
  return <style>{CUSTOMER_PAGE_STYLES}</style>;
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

export function PanelCardHeader({
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
  const targetName = targetDisplayName(data, targetId, embeddedTarget);
  return `${checkName} · ${targetName}`;
}

function evidenceDisplayLabel(item: DataItem) {
  return getString(item, ['title', 'label'], '') || getString(item, ['kind', 'type'], 'Evidence record');
}

function highScaleRequestLabel(data: PortalData, request: DataItem) {
  const objective = getString(request, ['objective', 'reason'], '').trim();
  if (objective) return objective;
  const ids = Array.isArray(request.target_ids) ? request.target_ids.map(String) : request.target_id ? [String(request.target_id)] : [];
  return ids.length ? ids.map((id) => targetDisplayName(data, id)).join(', ') : 'Domain scope not recorded';
}

type ReportExportFormat = 'json' | 'markdown' | 'html';

export type ReportExportRecord = {
  reportId: string;
  format: ReportExportFormat;
  exportedAt: string;
  contentSha256: string;
  artifactId: string;
  schemaVersion: string;
  textPreview: string;
  verification: { status: 'not_requested' | 'verifying' | 'verified' | 'failed' | 'error'; detail: string; at: string };
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
  { value: 'audit', label: 'Audit' },
  { value: 'soc2', label: 'SOC 2' },
  { value: 'iso27001', label: 'ISO 27001' },
  { value: 'dora', label: 'DORA' },
  { value: 'nis2', label: 'NIS2' },
  { value: 'internal_audit', label: 'Internal audit' }
];

export const REPORT_FORMAT_FALLBACK_OPTIONS: SelectOption[] = [
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

/** Report kinds are audiences or framework mappings; SOC operational reports are deferred. */
const REPORT_AUDIENCE_KINDS: Record<string, string> = {
  executive: 'Leadership summary of readiness and open gaps.',
  board: 'Risk and resilience summary for a board or risk committee.',
  technical: 'Engineering detail: recorded runs, verdicts, and findings.',
  audit: 'Evidence references and custody metadata for reviewers.',
  internal_audit: 'Internal audit view of controls and evidence references.'
};
const REPORT_FRAMEWORK_KINDS = new Set(['soc2', 'iso27001', 'dora', 'nis2']);
const REPORT_DEFERRED_KINDS = new Set(['soc']);

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

export function reportKindLabel(kind: string, options: SelectOption[] = REPORT_KIND_FALLBACK_OPTIONS) {
  return options.find((option) => option.value === kind)?.label ?? humanizeOptionValue(kind || 'report');
}

export function reportKindIsFramework(kind: string) {
  return REPORT_FRAMEWORK_KINDS.has(kind);
}

/** Explicit export (download) and separate, explicit custody verification. Nothing runs on open. */
export function useReportExport(config: PortalConfig, session: Session, onRefresh: () => Promise<void>) {
  const [busy, setBusy] = useState('');
  const [error, setError] = useState('');
  const [message, setMessage] = useState('');
  const [record, setRecord] = useState<ReportExportRecord | null>(null);
  const exportedJson = useRef<{ payload: DataItem; custody: DataItem } | null>(null);

  async function exportReport(reportId: string, format: ReportExportFormat, title: string) {
    if (!reportId) return;
    setBusy(`export-${format}`);
    setError('');
    setMessage('');
    try {
      const headers = buildApiHeaders(config, session);
      const response = await fetch(`/v1/reports/${encodeURIComponent(reportId)}/export?format=${format}`, { headers });
      if (!response.ok) {
        const payload = await response.json().catch(() => null);
        throw new Error(
          String(payload?.message ?? '').trim()
            || humanizeErrorCode(payload?.error)
            || (response.status === 403 ? 'Your role cannot export this report.' : `Export returned ${response.status}`)
        );
      }
      const ext = format === 'markdown' ? 'md' : format;
      const download = (content: string, mime: string) => {
        const blob = new Blob([content], { type: mime });
        const url = URL.createObjectURL(blob);
        const anchor = document.createElement('a');
        anchor.href = url;
        anchor.download = `${reportId}.${ext}`;
        document.body.appendChild(anchor);
        anchor.click();
        anchor.remove();
        setTimeout(() => URL.revokeObjectURL(url), 0);
      };
      const exportedAt = new Date().toISOString();
      if (format === 'json') {
        const exported = await response.json() as DataItem;
        const custody = getNestedItem(exported, ['custody']);
        const payload = getNestedItem(exported, ['payload']);
        exportedJson.current = custody && payload ? { payload, custody } : null;
        setRecord({
          reportId,
          format,
          exportedAt,
          contentSha256: getString(custody ?? {}, ['content_sha256'], ''),
          artifactId: getString(custody ?? {}, ['artifact_id'], ''),
          schemaVersion: getString(custody ?? {}, ['schema_version'], ''),
          textPreview: '',
          verification: { status: 'not_requested', detail: '', at: '' }
        });
        download(JSON.stringify(exported, null, 2), 'application/json');
      } else {
        const text = await response.text();
        exportedJson.current = null;
        setRecord({
          reportId,
          format,
          exportedAt,
          contentSha256: '',
          artifactId: '',
          schemaVersion: '',
          textPreview: text.slice(0, 900),
          verification: { status: 'not_requested', detail: '', at: '' }
        });
        download(text, format === 'markdown' ? 'text/markdown' : 'text/html');
      }
      setMessage(`Exported "${title}" as ${format === 'markdown' ? 'Markdown' : format.toUpperCase()}. The file reflects the report snapshot, not current status.`);
      await onRefresh().catch(() => undefined);
    } catch (err) {
      setError(apiErrorMessage(err, 'Report export failed. The report is unchanged.'));
    } finally {
      setBusy('');
    }
  }

  async function verifyCustody() {
    const source = exportedJson.current;
    if (!source || !record) return;
    setBusy('verify');
    setError('');
    setRecord({ ...record, verification: { status: 'verifying', detail: '', at: '' } });
    try {
      const verified = await requestJson(config, session, '/v1/custody/verify', { method: 'POST', body: source }) as DataItem;
      const verification = getNestedItem(verified, ['verification']) ?? verified;
      const ok = verification.ok === true;
      const failed = verification.ok === false;
      setRecord((current) => current ? {
        ...current,
        verification: {
          status: ok ? 'verified' : failed ? 'failed' : 'error',
          detail: ok
            ? 'The server recomputed the digest of this exported content and it matches the custody manifest. It does not re-verify the stored report.'
            : failed
              ? `The server recomputed the digest and it does not match${getString(verification, ['error'], '') ? ` (${getString(verification, ['error'], '')})` : ''}. Treat this export as untrusted.`
              : 'The server returned no verification outcome.',
          at: getString(verification, ['verified_at'], '')
        }
      } : current);
    } catch (err) {
      setRecord((current) => current ? { ...current, verification: { status: 'error', detail: apiErrorMessage(err, 'Verification request failed.'), at: '' } } : current);
    } finally {
      setBusy('');
    }
  }

  return { busy, error, message, record, exportReport, verifyCustody, canVerify: Boolean(exportedJson.current) };
}

export function ReportExportMenu({
  reportId,
  title,
  formats,
  exporter,
  disabled = false
}: {
  reportId: string;
  title: string;
  formats: SelectOption[];
  exporter: ReturnType<typeof useReportExport>;
  disabled?: boolean;
}) {
  const [open, setOpen] = useState(false);
  const menuId = `report-export-${reportId}`;
  const containerRef = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!open) return undefined;
    function onPointer(event: PointerEvent) {
      if (!containerRef.current?.contains(event.target as Node)) setOpen(false);
    }
    document.addEventListener('pointerdown', onPointer);
    return () => document.removeEventListener('pointerdown', onPointer);
  }, [open]);
  return (
    <div
      className="report-export-menu"
      ref={containerRef}
      onKeyDown={(event) => {
        if (event.key === 'Escape' && open) {
          event.stopPropagation();
          setOpen(false);
          containerRef.current?.querySelector<HTMLButtonElement>('button')?.focus();
        }
      }}
    >
      <Button
        size="sm"
        variant="secondary"
        aria-expanded={open}
        aria-controls={open ? menuId : undefined}
        loading={exporter.busy.startsWith('export-')}
        disabled={disabled || exporter.busy !== ''}
        onClick={() => setOpen((value) => !value)}
      >
        Export
      </Button>
      {open ? (
        <ul className="report-export-options" id={menuId} aria-label={`Export ${title}`}>
          {formats.map((format) => (
            <li key={format.value}>
              <button
                type="button"
                onClick={() => {
                  setOpen(false);
                  void exporter.exportReport(reportId, format.value as ReportExportFormat, title);
                }}
              >
                <span>{format.label}</span>
                <small>{format.value === 'json' ? 'Includes a custody manifest you can verify' : format.value === 'html' ? 'Readable document; print to PDF yourself if needed' : 'Plain text for tickets and wikis'}</small>
              </button>
            </li>
          ))}
        </ul>
      ) : null}
    </div>
  );
}

export function ReportExportResult({ exporter }: { exporter: ReturnType<typeof useReportExport> }) {
  const record = exporter.record;
  if (!record) return null;
  const verification = record.verification;
  return (
    <Card className="card--dense report-export-result" aria-live="polite">
      <PanelCardHeader
        title="Last export"
        description={`${record.format === 'markdown' ? 'Markdown' : record.format.toUpperCase()} downloaded ${formatDate(record.exportedAt)}. Exporting again creates a new file from the same snapshot.`}
      />
      <CardContent className="stack-tight">
        {record.format === 'json' ? (
          <>
            <div className="kv-list">
              <div><span>Recorded digest (SHA-256)</span><strong className="cp-mono-wrap">{record.contentSha256 || 'Not returned'}</strong></div>
              <div><span>Artifact</span><strong className="cp-mono-wrap">{record.artifactId || 'Not returned'}</strong></div>
              <div><span>Schema</span><strong>{record.schemaVersion || 'Not returned'}</strong></div>
              <div>
                <span>Server verification</span>
                <strong>
                  {verification.status === 'not_requested' ? 'Not verified yet'
                    : verification.status === 'verifying' ? 'Verifying…'
                      : verification.status === 'verified' ? `Verified by the server${verification.at ? ` ${formatDate(verification.at)}` : ''}`
                        : verification.status === 'failed' ? `Failed${verification.at ? ` ${formatDate(verification.at)}` : ''}`
                          : 'Verification unavailable'}
                </strong>
              </div>
            </div>
            {verification.detail ? <p className={verification.status === 'failed' || verification.status === 'error' ? 'form-banner error' : 'muted small'}>{verification.detail}</p> : null}
            <p className="muted small">A recorded digest is not proof on its own. Verification asks the server to recompute it and records an audit entry.</p>
            <div className="row-actions">
              <Button size="sm" variant="secondary" loading={exporter.busy === 'verify'} disabled={!exporter.canVerify || exporter.busy !== ''} onClick={() => void exporter.verifyCustody()}>
                Verify custody
              </Button>
            </div>
          </>
        ) : (
          <>
            <p className="muted small">No custody manifest for this format. Export JSON to verify integrity.</p>
            <pre className="codeblock" tabIndex={0} aria-label="First 900 characters of the export">{record.textPreview}</pre>
          </>
        )}
      </CardContent>
    </Card>
  );
}

type ReportScopeMode = 'tenant' | 'targets';
type ScopeList = { status: 'idle' | 'loading' | 'loaded' | 'error'; items: DataItem[]; error: string };

/** Plain description of a scope rejection, keeping the server's exact ids and limits. */
export function describeReportScopeError(payload: DataItem | null | undefined) {
  const code = getString(payload ?? {}, ['error'], '');
  const ids = (key: string) => (Array.isArray(payload?.[key]) ? (payload![key] as unknown[]).map(String).join(', ') : '');
  switch (code) {
    case 'unknown_target': return `These targets were not found in this workspace: ${ids('target_ids')}. Remove them from the scope.`;
    case 'unknown_target_group': return 'This saved scope is unavailable. Select declared domains directly.';
    case 'inactive_target': return `These targets are removed and cannot be reported on: ${ids('target_ids')}.`;
    case 'inactive_target_group': return 'This saved scope is unavailable. Select active declared domains.';
    case 'scope_too_large': return `The scope is too large: ${getString(payload ?? {}, ['count'], 'more than allowed')} ${getString(payload ?? {}, ['field'], 'items') === 'declared_members' ? 'declared targets' : 'entries'}, limit ${getString(payload ?? {}, ['limit'], 'set by the server')}. Choose fewer domains.`;
    case 'scope_mismatch': return 'The selected domain scope is inconsistent. Review the declared domains.';
    case 'invalid_scope': return `The scope was rejected (${getString(payload ?? {}, ['field'], 'scope')}: ${getString(payload ?? {}, ['reason'], 'invalid').replaceAll('_', ' ')}).`;
    case 'unrecognized_scope': return `The scope used unsupported fields: ${ids('fields')}.`;
    case 'unsupported_period': return 'That period is not supported. Choose a listed period.';
    default: return code ? `Report generation was rejected: ${code.replaceAll('_', ' ')}.` : '';
  }
}

function readinessStatusText(summary: DataItem | null) {
  const status = getString(summary ?? {}, ['readiness_score_status'], '');
  const reason = getString(summary ?? {}, ['readiness_score_reason'], '');
  if (status === 'published') return null;
  if (reason === 'published_readiness_formula_is_tenant_wide') return 'Not included: the published readiness formula covers the whole workspace, so a scoped report has no score.';
  if (status === 'unknown') return `Not included: ${reason ? reason.replaceAll('_', ' ') : 'readiness was unavailable at generation'}.`;
  return null;
}

export function ReportSnapshotPreview({ report, formats, exporter }: { report: DataItem; formats: SelectOption[]; exporter: ReturnType<typeof useReportExport> }) {
  const summary = getNestedItem(report, ['summary']);
  const scope = getNestedItem(summary, ['scope']);
  const members = getNestedItem(scope, ['declared_members']);
  const runCapture = getNestedItem(summary, ['run_capture']);
  const findingsSnapshot = getNestedItem(summary, ['findings_snapshot']);
  const readinessText = readinessStatusText(summary);
  const score = getOptionalNumber(summary, ['readiness_score']);
  const mode = getString(scope ?? {}, ['mode'], '');
  const id = getString(report, ['id'], '');
  const title = getString(report, ['title'], 'Generated report');
  const count = (item: DataItem | null, includedKey = 'included') => {
    const included = getOptionalNumber(item, [includedKey]);
    const total = getOptionalNumber(item, ['total']);
    if (included === null) return 'Not recorded';
    return total === null ? `${formatNumber(included)} (total not recorded)` : `${formatNumber(included)} of ${formatNumber(total)}`;
  };
  return (
    <Card className="card--dense report-generated-preview" aria-live="polite">
      <PanelCardHeader
        title={`Generated: ${title}`}
        description={`Snapshot frozen ${getString(summary ?? {}, ['as_of'], '') ? formatDate(getString(summary ?? {}, ['as_of'], '')) : 'at an unrecorded time'}. Nothing is exported until you choose a format.`}
        trailing={(
          <div className="row-actions">
            <AnchorButton size="sm" variant="secondary" href={buildDetailHref('report-detail', id)}>Open report</AnchorButton>
            <ReportExportMenu reportId={id} title={title} formats={formats} exporter={exporter} />
          </div>
        )}
      />
      <CardContent className="kv-list">
        <div><span>Scope</span><strong>{mode === 'tenant' || !mode ? 'Whole workspace' : mode === 'target_groups' ? 'Historical domain scope' : mode === 'targets' ? `${formatNumber(Array.isArray(scope?.target_ids) ? (scope!.target_ids as unknown[]).length : 0)} target(s)` : mode.replaceAll('_', ' ')}</strong></div>
        <div><span>Declared targets captured</span><strong>{count(members)}</strong></div>
        <div><span>Runs captured</span><strong>{count(runCapture)}{getString(runCapture ?? {}, ['limit'], '') ? ` (most recent, limit ${getString(runCapture ?? {}, ['limit'], '')})` : ''}</strong></div>
        <div><span>Findings captured</span><strong>{count(findingsSnapshot)}</strong></div>
        <div><span>Readiness score</span><strong>{score !== null ? `${formatNumber(score)} / 100 (workspace formula)` : readinessText ?? 'Not recorded'}</strong></div>
      </CardContent>
      <CardContent><ReportExportResult exporter={exporter} /></CardContent>
    </Card>
  );
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
  const [reportKind, setReportKind] = useState('');
  const [reportPeriod, setReportPeriod] = useState('');
  const [reviewing, setReviewing] = useState(false);
  const [created, setCreated] = useState<DataItem | null>(null);
  const [caller] = useState(() => ({ targetId: getHashQueryParam('target'), scoped: Boolean(getHashQueryParam('target') || getHashQueryParam('group')) }));
  const [scopeMode, setScopeMode] = useState<ReportScopeMode>(() => (caller.scoped ? 'targets' : 'tenant'));
  const [selectedTargetIds, setSelectedTargetIds] = useState<string[]>(() => (caller.targetId ? [caller.targetId] : []));
  const [scopeQuery, setScopeQuery] = useState('');
  const [targetList, setTargetList] = useState<ScopeList>({ status: 'idle', items: [], error: '' });
  const [scopeReload, setScopeReload] = useState(0);
  const reviewHeadingRef = useRef<HTMLHeadingElement>(null);
  const exporter = useReportExport(config, session, onRefresh);
  const reports = data.reports;
  const canCreateReport = sessionHasPermission(session, 'report:create');
  const reportKindOptions = reportOptionsFromCapabilities(data.reportCapabilities, 'kinds', REPORT_KIND_FALLBACK_OPTIONS)
    .filter((option) => !REPORT_DEFERRED_KINDS.has(option.value));
  const audienceOptions = reportKindOptions.filter((option) => !REPORT_FRAMEWORK_KINDS.has(option.value));
  const frameworkOptions = reportKindOptions.filter((option) => REPORT_FRAMEWORK_KINDS.has(option.value));
  const reportPeriodOptions = reportOptionsFromCapabilities(data.reportCapabilities, 'periods', REPORT_PERIOD_FALLBACK_OPTIONS);
  const formatOptions = reportOptionsFromCapabilities(data.reportCapabilities, 'formats', REPORT_FORMAT_FALLBACK_OPTIONS);
  const selectedReportKind = reportKindOptions.some((option) => option.value === reportKind) ? reportKind : '';
  const selectedReportPeriod = clampOptionValue(reportPeriodOptions, reportPeriod || getString(data.reportCapabilities ?? {}, ['default_period'], 'last-30-days'));
  const kindLabel = selectedReportKind ? reportKindLabel(selectedReportKind, reportKindOptions) : '';
  const periodLabel = reportPeriodOptions.find((option) => option.value === selectedReportPeriod)?.label ?? selectedReportPeriod;
  const reportTitle = selectedReportKind ? `${kindLabel} readiness report` : '';
  const scopeCaps = getNestedItem(data.reportCapabilities ?? {}, ['scope']);
  const scopeFields = Array.isArray(scopeCaps?.fields) ? (scopeCaps!.fields as unknown[]).map(String) : [];
  const scopeLimit = getOptionalNumber(scopeCaps, ['max_ids']);
  const memberCap = getOptionalNumber(scopeCaps, ['declared_members_cap']);
  const runCaptureLimit = getOptionalNumber(getNestedItem(data.reportCapabilities ?? {}, ['capture']), ['runs_when_run_ids_omitted']);
  const modeSupported = (mode: ReportScopeMode) => mode === 'tenant'
    || (scopeLimit !== null && scopeFields.includes('target_ids'));
  const scopeModeSupported = modeSupported(scopeMode);

  useEffect(() => {
    if (!canCreateReport || !scopeModeSupported) return undefined;
    let cancelled = false;
    const load = async (path: string, set: (value: ScopeList) => void) => {
      set({ status: 'loading', items: [], error: '' });
      try {
        const payload = await requestJson(config, session, path) as DataItem;
        if (!cancelled) set({ status: 'loaded', items: Array.isArray(payload?.items) ? payload.items as DataItem[] : [], error: '' });
      } catch (err) {
        if (!cancelled) set({ status: 'error', items: [], error: apiErrorMessage(err, 'Could not load the list.') });
      }
    };
    if (scopeMode === 'targets' && targetList.status === 'idle') void load('/v1/targets', setTargetList);
    return () => { cancelled = true; };
    // Lists load once per mode on demand; Retry resets them to idle.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [scopeMode, scopeReload, canCreateReport, scopeModeSupported]);

  useEffect(() => {
    if (reviewing) reviewHeadingRef.current?.focus();
  }, [reviewing]);

  const activeList = targetList;
  const selectedIds = selectedTargetIds;
  const listItems = targetList.items.filter((target) => !target.deleted_at && !target.archived_at);
  const itemLabel = (item: DataItem) => getString(item, ['value', 'hostname'], 'Declared domain');
  const knownIds = new Set(listItems.map((item) => getString(item, ['id'], '')));
  const unresolvedIds = activeList.status === 'loaded' ? selectedIds.filter((id) => !knownIds.has(id)) : [];
  const scopeQueryText = scopeQuery.trim().toLowerCase();
  const visibleItems = listItems
    .filter((item) => !scopeQueryText || `${itemLabel(item)} ${getString(item, ['id'], '')}`.toLowerCase().includes(scopeQueryText))
    .slice(0, 200);
  const scopeReady = scopeMode === 'tenant'
    || (scopeModeSupported && scopeLimit !== null && selectedIds.length > 0 && selectedIds.length <= scopeLimit && unresolvedIds.length === 0 && activeList.status === 'loaded');
  const scopeSummary = scopeMode === 'tenant'
    ? 'Whole workspace (no scope sent)'
    : `${formatNumber(selectedIds.length)} ${'domain'}${selectedIds.length === 1 ? '' : 's'} selected`;
  const generateBlocked = !selectedReportKind || !scopeReady;

  function setMode(next: ReportScopeMode) {
    setScopeMode(next);
    setScopeQuery('');
    setReviewing(false);
  }

  function toggleSelection(id: string) {
    setReviewing(false);
    const update = (current: string[]) => current.includes(id) ? current.filter((value) => value !== id) : [...current, id];
    setSelectedTargetIds(update);
  }

  const reportColumns: TableColumn<DataItem>[] = [
    {
      key: 'report',
      label: 'Report',
      render: (item) => {
        const kind = getString(item, ['kind'], '');
        return (
          <div className="cp-stack">
            <a className="cp-link" href={buildDetailHref('report-detail', getString(item, ['id'], ''))}>{getString(item, ['title'], `${reportKindLabel(kind)} report`)}</a>
            <span className="muted small">{reportKindIsFramework(kind) ? `${reportKindLabel(kind)} mapping` : `${reportKindLabel(kind)} audience`}</span>
          </div>
        );
      }
    },
    {
      key: 'period',
      label: 'Period',
      render: (item) => {
        const value = getString(item, ['period', 'reporting_period', 'window'], '');
        if (!value) return <span className="muted">Not recorded</span>;
        return reportPeriodOptions.find((option) => option.value === value)?.label ?? humanizeOptionValue(value);
      }
    },
    {
      key: 'scope',
      label: 'Scope',
      render: (item) => {
        const scope = getNestedItem(item, ['summary', 'scope']);
        const mode = getString(scope ?? {}, ['mode'], '');
        if (!scope) return <span className="muted">Not recorded (legacy report)</span>;
        if (mode === 'tenant') return 'Whole workspace';
        const legacyScope = scope.mode === 'target_groups';
        const targets = Array.isArray(scope.target_ids) ? scope.target_ids.length : 0;
        const runs = getNestedItem(item, ['summary', 'run_capture']);
        return [legacyScope ? 'Historical domain scope' : '', targets ? `${formatNumber(targets)} target${targets === 1 ? '' : 's'}` : '', mode === 'runs' ? `${getString(runs ?? {}, ['included'], '?')} runs` : ''].filter(Boolean).join(' · ') || mode.replaceAll('_', ' ');
      }
    },
    { key: 'generated', label: 'Generated', render: (item) => <span className="mono">{formatDate(getNestedItem(item, ['summary'])?.as_of ?? item.created_at ?? item.generated_at)}</span> },
    { key: 'status', label: 'Status', render: (item) => <Badge tone="muted">{getString(item, ['status'], 'Not recorded').replaceAll('_', ' ')}</Badge> }
  ];

  async function handleGenerate() {
    if (!canCreateReport || generateBlocked) return;
    setBusy('create-report');
    setError('');
    setMessage('');
    setCreated(null);
    const body: Record<string, unknown> = { title: reportTitle, kind: selectedReportKind, period: selectedReportPeriod };
    if (scopeMode === 'targets') body.target_ids = [...selectedTargetIds];
    try {
      const result = await requestJson(config, session, '/v1/reports', { method: 'POST', body }) as DataItem;
      if (getString(result, ['error'], '')) {
        setError(describeReportScopeError(result) || 'Report generation was rejected.');
        return;
      }
      setCreated(result);
      setReviewing(false);
      setMessage(`Generated "${getString(result, ['title'], reportTitle)}". Review the snapshot below, then export if you need a file.`);
      await onRefresh().catch(() => undefined);
    } catch (err) {
      const payload = (err as { payload?: unknown })?.payload as DataItem | undefined;
      setError(describeReportScopeError(payload) || apiErrorMessage(err, 'Report generation failed. Your choices are kept.'));
    } finally {
      setBusy('');
    }
  }

  const selectedNames = selectedIds.map((id) => {
    const match = listItems.find((item) => getString(item, ['id'], '') === id);
    return { id, label: match ? itemLabel(match) : id, known: Boolean(match) };
  });

  return (
    <div className="content reports-page">
      <CustomerPageStyles />
      <PageHeader
        route="reports"
        title="Reports"
        eyebrow="Snapshots on the record"
        description="Generate a dated snapshot of findings, recorded runs, and declarations for a chosen audience and scope, review it, then export it. A report never changes after generation."
      />
      {error ? <div className="form-banner error" role="alert">{error}</div> : null}
      {message && !error ? <Toast message={message} tone="success" duration={5000} /> : null}
      {created ? <ReportSnapshotPreview report={created} formats={formatOptions} exporter={exporter} /> : null}
      {canCreateReport ? (
        <Card>
          <PanelCardHeader title="New report" description="Choose the audience, period, and exact scope, review, then generate. Export happens afterwards, only when you choose a format." />
          <CardContent className="stack">
            <fieldset className="report-kind-group" disabled={busy !== ''}>
              <legend>1. Audience</legend>
              <div className="report-kind-options">
                {audienceOptions.map((option) => (
                  <label key={option.value} className="report-kind-option">
                    <input type="radio" name="report_kind" value={option.value} checked={selectedReportKind === option.value} onChange={() => { setReportKind(option.value); setReviewing(false); }} />
                    <span><strong>{option.label}</strong><small>{REPORT_AUDIENCE_KINDS[option.value] ?? 'Recorded readiness summary.'}</small></span>
                  </label>
                ))}
              </div>
            </fieldset>
            {frameworkOptions.length ? (
              <fieldset className="report-kind-group" disabled={busy !== ''}>
                <legend>Or a framework mapping</legend>
                <p className="cp-note">Maps recorded evidence to framework controls. It is not a certification or a statement of compliance.</p>
                <div className="report-kind-options">
                  {frameworkOptions.map((option) => (
                    <label key={option.value} className="report-kind-option">
                      <input type="radio" name="report_kind" value={option.value} checked={selectedReportKind === option.value} onChange={() => { setReportKind(option.value); setReviewing(false); }} />
                      <span><strong>{option.label}</strong><small>Control mapping</small></span>
                    </label>
                  ))}
                </div>
              </fieldset>
            ) : null}
            <div className="product-form">
              <Select label="2. Period" name="period" value={selectedReportPeriod} options={reportPeriodOptions} onChange={(value) => { setReportPeriod(value); setReviewing(false); }} hint="Runs and findings are captured inside this window, ending at generation." />
            </div>
            <fieldset className="report-kind-group" disabled={busy !== ''}>
              <legend>3. Scope</legend>
              <div className="cp-toolbar" role="radiogroup" aria-label="Report scope">
                <label className="check-row"><input type="radio" name="report_scope" checked={scopeMode === 'tenant'} onChange={() => setMode('tenant')} /><span>Whole workspace</span></label>
                <label className="check-row"><input type="radio" name="report_scope" checked={scopeMode === 'targets'} disabled={!modeSupported('targets')} onChange={() => setMode('targets')} /><span>Selected domains{modeSupported('targets') ? '' : ' (not offered by this server)'}</span></label>
              </div>
              {!scopeModeSupported ? (
                <div className="form-banner error" role="alert">
                  {data.reportCapabilities ? 'This server does not advertise' : 'Report capabilities could not be read, so this page cannot confirm support for'} domain-scoped reports. {caller.scoped ? 'The saved scope was not applied and no other domain was selected. ' : ''}Choose Whole workspace explicitly to continue.
                </div>
              ) : null}
              {caller.targetId ? (
                <p className="cp-note">Started from a declared domain; that exact domain is preselected.</p>
              ) : null}
              {scopeMode !== 'tenant' && scopeModeSupported ? (
                <div className="report-scope-picker stack-tight">
                  {activeList.status === 'loading' || activeList.status === 'idle' ? <p className="muted small" role="status">Loading declared domains…</p> : null}
                  {activeList.status === 'error' ? (
                    <div className="form-banner error row-actions" role="alert">
                      <span>{activeList.error}</span>
                      <Button size="sm" variant="secondary" onClick={() => { setTargetList({ status: 'idle', items: [], error: '' }); setScopeReload((count) => count + 1); }}>Retry</Button>
                    </div>
                  ) : null}
                  {unresolvedIds.length ? (
                    <div className="form-banner error" role="alert">
                      Not visible in this workspace: {unresolvedIds.join(', ')}. Nothing else was selected in its place.{' '}
                      {unresolvedIds.map((id) => <Button key={id} size="sm" variant="secondary" onClick={() => toggleSelection(id)}>Remove {id}</Button>)}
                    </div>
                  ) : null}
                  {activeList.status === 'loaded' ? (
                    <>
                      <label className="field">
                        <span>Find a domain</span>
                        <input className="input" type="search" value={scopeQuery} onChange={(event) => setScopeQuery(event.target.value)} placeholder="Hostname, URL, or IP" autoComplete="off" />
                      </label>
                      <p className="muted small" aria-live="polite">{scopeSummary}{scopeLimit !== null && selectedIds.length > scopeLimit ? ` · more than ${formatNumber(scopeLimit)} is not allowed` : ''}{listItems.length > visibleItems.length ? ` · first ${visibleItems.length} of ${listItems.length} matches shown` : ''}</p>
                      {listItems.length === 0 ? (
                        <p className="cp-note">No active domains have been declared.</p>
                      ) : (
                        <ul className="report-scope-options" aria-label="Declared domains">
                          {visibleItems.map((item) => {
                            const id = getString(item, ['id'], '');
                            return (
                              <li key={id}>
                                <label className="check-row">
                                  <input type="checkbox" checked={selectedIds.includes(id)} onChange={() => toggleSelection(id)} />
                                  <span className="cp-stack">
                                    <span>{itemLabel(item)}</span>
                                    <span className="muted small mono">{id}</span>
                                  </span>
                                </label>
                              </li>
                            );
                          })}
                        </ul>
                      )}
                    </>
                  ) : null}
                  <p className="muted small">
                    Up to {scopeLimit !== null ? formatNumber(scopeLimit) : 'the server limit of'} domains per report
                    . The server rejects a larger scope rather than trimming it.
                  </p>
                </div>
              ) : scopeMode === 'tenant' ? <p className="cp-note">Covers every declared target. No scope is sent with the request.</p> : null}
            </fieldset>
            <div className="row-actions">
              <Button variant="secondary" disabled={!selectedReportKind || !scopeReady || busy !== ''} onClick={() => setReviewing(true)}>Review report</Button>
              {!selectedReportKind ? <span className="muted small">Choose an audience or framework first.</span> : !scopeModeSupported ? <span className="muted small">This scope is not offered; choose Whole workspace.</span> : !scopeReady ? <span className="muted small">Select at least one domain that is visible in this workspace.</span> : null}
            </div>
            {reviewing && selectedReportKind && scopeReady ? (
              <section className="report-review" aria-labelledby="report-review-heading">
                <h3 id="report-review-heading" ref={reviewHeadingRef} tabIndex={-1}>Review before generating</h3>
                <dl className="kv-list">
                  <div><dt>Title</dt><dd>{reportTitle}</dd></div>
                  <div><dt>{reportKindIsFramework(selectedReportKind) ? 'Framework mapping' : 'Audience'}</dt><dd>{kindLabel}</dd></div>
                  <div><dt>Period</dt><dd>{periodLabel}, ending at generation</dd></div>
                  <div><dt>Scope</dt><dd>{scopeMode === 'tenant' ? 'Whole workspace' : selectedNames.map((entry) => entry.label).join(', ')}</dd></div>
                  <div><dt>Captured at generation</dt><dd>Declared targets in scope, findings and recorded runs inside the period ({runCaptureLimit !== null ? `up to the ${formatNumber(runCaptureLimit)} most recent runs` : 'most recent runs, bounded by the server'}), verdicts, and evidence references</dd></div>
                  <div><dt>Readiness score</dt><dd>{scopeMode === 'tenant' ? 'Included: the published workspace formula' : 'Not included: the published formula covers the whole workspace'}</dd></div>
                  <div><dt>Not included</dt><dd>Protection profiles, and anything that changes after generation</dd></div>
                </dl>
                {reportKindIsFramework(selectedReportKind) ? <p className="cp-note">Framework mappings describe how evidence relates to controls. They do not certify compliance.</p> : null}
                <div className="row-actions">
                  <Button variant="ghost" disabled={busy !== ''} onClick={() => setReviewing(false)}>Change choices</Button>
                  <Button loading={busy === 'create-report'} disabled={generateBlocked || busy !== ''} onClick={() => void handleGenerate()}>Generate report</Button>
                </div>
              </section>
            ) : null}
          </CardContent>
        </Card>
      ) : <RoleRestrictedCard title="Report generation is not available for your role." />}
      <Card className="card--dense">
        <PanelCardHeader title="Generated reports" description="Newest first. Open a report to read its snapshot and export it." />
        <CardContent>
          <DataTable
            columns={reportColumns}
            items={reports}
            loadError={data.loadErrors.reports}
            onRetry={() => void onRefresh()}
            getRowId={(item) => getString(item, ['id'], '')}
            selectedId={getString(created ?? {}, ['id'], '') || null}
            getRowProps={(item) => {
              const id = getString(item, ['id'], '');
              return id ? detailRowProps('report-detail', id, `Open report ${getString(item, ['title'], id)}`) : {};
            }}
            empty={<EmptyState icon={FileText} title="No reports generated yet." body={canCreateReport ? 'Choose an audience above to generate the first snapshot.' : 'Ask an owner or admin to generate one.'} />}
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
  const [tab, setTabState] = useState<SettingsTab>(() => {
    const requested = getHashQueryParam('tab');
    return SETTINGS_TAB_OPTIONS.some((option) => option.id === requested) ? requested as SettingsTab : 'organization';
  });
  const [secretAcknowledged, setSecretAcknowledged] = useState(false);
  const [secretRevealed, setSecretRevealed] = useState(false);
  const createVaultFormRef = useRef<HTMLFormElement>(null);
  const rotateVaultFormRef = useRef<HTMLFormElement>(null);
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
  const [retentionError, setRetentionError] = useState('');
  const tenant = data.tenant;
  const privacy = getNestedItem(tenant, ['privacy_settings']) ?? {};
  const evidenceRetention = getNestedItem(privacy, ['evidence_retention']) ?? {};
  const recordedMetadataRetentionDays = getOptionalNumber(privacy, ['metadata_retention_days']);
  const metadataRetentionDays = recordedMetadataRetentionDays ?? 90;
  const recordedReportDays = getOptionalNumber(evidenceRetention, ['report_days']);
  const recordedAuditDays = getOptionalNumber(evidenceRetention, ['audit_log_days']);
  const recordedHighScaleDays = getOptionalNumber(evidenceRetention, ['high_scale_artifact_days']);

  function setTab(next: SettingsTab) {
    if (tab === 'security' && next !== 'security') {
      createVaultFormRef.current?.reset();
      rotateVaultFormRef.current?.reset();
    }
    setTabState(next);
    replaceRouteParams({ tab: next === 'organization' ? null : next });
  }

  function showOneTimeSecret(label: string, value: string) {
    setSecretAcknowledged(false);
    setSecretRevealed(false);
    setOneTimeSecret({ label, value });
  }
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
    { key: 'name', label: 'Account', render: (item) => <span className="cp-stack"><span>{getString(item, ['name'], 'Unnamed account')}</span><span className="mono muted small">{getString(item, ['id'], '')}</span></span> },
    { key: 'role', label: 'Role', render: (item) => <Badge tone="muted">{getString(item, ['role'])}</Badge> },
    { key: 'scopes', label: 'Scopes', render: (item) => Array.isArray(item.scopes) ? item.scopes.join(', ') : 'Not recorded' },
    { key: 'expires', label: 'Expires', render: (item) => item.expires_at ? formatDate(item.expires_at) : 'No expiry set' },
    { key: 'state', label: 'State', render: (item) => {
      const expired = !item.revoked_at && item.expires_at && Date.parse(String(item.expires_at)) <= Date.now();
      return <Badge tone={item.revoked_at || expired ? 'muted' : 'info'}>{item.revoked_at ? 'Revoked' : expired ? 'Expired' : 'Active'}</Badge>;
    } },
    {
      key: 'actions',
      label: 'Actions',
      render: (item) => {
        const id = getString(item, ['id'], '');
        if (!canRotateServiceAccount && !canRevokeServiceAccount) return <span className="muted">Read only</span>;
        return (
          <div className="row-actions">
            {canRotateServiceAccount ? <Button size="sm" variant="secondary" loading={busy === `rotate-service-${id}`} disabled={busy !== '' || Boolean(item.revoked_at)} onClick={() => void rotateServiceAccount(item)} aria-label={`Rotate secret for ${getString(item, ['name', 'id'])}`}>Rotate</Button> : null}
            {canRevokeServiceAccount ? <Button size="sm" variant="danger" loading={busy === `revoke-service-${id}`} disabled={busy !== '' || Boolean(item.revoked_at)} onClick={() => void revokeServiceAccount(item)} aria-label={`Revoke ${getString(item, ['name', 'id'])}`}>Revoke</Button> : null}
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
    if (requestedScopes.some((scope) => !/^[a-z_]+:[a-z_]+$/.test(scope))) {
      setError('Scopes must look like resource:action, separated by commas, for example evidence:read.');
      return;
    }
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
      showOneTimeSecret('New service account secret', String((result as { secret: string }).secret));
      formElement.reset();
    }
  }

  async function revokeServiceAccount(account: DataItem) {
    const id = getString(account, ['id'], '');
    if (!canRevokeServiceAccount || !id) return;
    const name = getString(account, ['name'], id);
    if (!await confirm({
      title: `Revoke ${name}`,
      description: `Revoke service account "${name}" (${id}, role ${getString(account, ['role'], 'not recorded')})? Every automation using its secret stops working immediately. Revocation cannot be undone; create a new account to restore access.`,
      confirmLabel: 'Revoke account',
      requireTypedId: name
    })) return;
    await runSettingsAction(`revoke-service-${id}`, () => requestJson(config, session, `/v1/service-accounts/${id}/revoke`, { method: 'POST' }), `Revoked "${name}". Its secret no longer works.`);
  }

  async function rotateServiceAccount(account: DataItem) {
    const id = getString(account, ['id'], '');
    if (!canRotateServiceAccount || !id) return;
    const name = getString(account, ['name'], id);
    if (!await confirm({
      title: `Rotate secret for ${name}`,
      description: `Issue a new secret for "${name}" (${id})? The current secret stops working immediately, so update every automation that uses it right after copying the new one. The new secret is shown once.`,
      confirmLabel: 'Rotate secret'
    })) return;
    const result = await runSettingsAction(`rotate-service-${id}`, () => requestJson(config, session, `/v1/service-accounts/${id}/rotate`, { method: 'POST' }), `Rotated "${name}". Copy the new secret now; it is shown once.`);
    if (result && typeof result === 'object' && 'secret' in result && typeof (result as { secret?: unknown }).secret === 'string') {
      showOneTimeSecret(`New secret for ${name}`, String((result as { secret: string }).secret));
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
    const values = {
      metadata_retention_days: Number(form.get('metadata_retention_days')),
      report_days: Number(form.get('report_days')),
      audit_log_days: Number(form.get('audit_log_days')),
      high_scale_artifact_days: Number(form.get('high_scale_artifact_days'))
    };
    const bounds: Record<keyof typeof values, [number, number, string]> = {
      metadata_retention_days: [1, 3650, 'Metadata retention'],
      report_days: [30, 3650, 'Report retention'],
      audit_log_days: [365, 3650, 'Audit log retention'],
      high_scale_artifact_days: [365, 3650, 'High-scale artifact retention']
    };
    for (const [key, [min, max, label]] of Object.entries(bounds) as Array<[keyof typeof values, [number, number, string]]>) {
      const value = values[key];
      if (!Number.isInteger(value) || value < min || value > max) {
        setRetentionError(`${label} must be a whole number of days from ${min} to ${max}.`);
        return;
      }
    }
    setRetentionError('');
    setPendingRetention({
      metadata_retention_days: values.metadata_retention_days,
      evidence_retention: {
        report_days: values.report_days,
        audit_log_days: values.audit_log_days,
        high_scale_artifact_days: values.high_scale_artifact_days,
        legal_hold: form.get('legal_hold') === 'on'
      }
    });
  }

  const retentionChanges = pendingRetention ? [
    { label: 'Metadata (events, vault metadata, notification history)', before: recordedMetadataRetentionDays, after: pendingRetention.metadata_retention_days },
    { label: 'Generated reports', before: recordedReportDays, after: pendingRetention.evidence_retention.report_days },
    { label: 'Audit log', before: recordedAuditDays, after: pendingRetention.evidence_retention.audit_log_days },
    { label: 'High-scale authorization artifacts', before: recordedHighScaleDays, after: pendingRetention.evidence_retention.high_scale_artifact_days }
  ] : [];
  const retentionReductions = retentionChanges.filter((change) => change.before !== null && change.after < change.before);

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
    if (!await confirm({ title: 'Store integration secret', description: `Store "${name}" (${purpose.replaceAll('_', ' ')}) in the encrypted tenant vault? The value is never shown again; only its name and purpose are listed.`, confirmLabel: 'Store secret', confirmTone: 'default' })) return;
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
    const secretRecord = data.secrets.find((secret) => getString(secret, ['id'], '') === id);
    if (!await confirm({ title: 'Rotate vault secret', description: `Replace the stored value of "${getString(secretRecord ?? {}, ['name'], id)}"? Connectors and workflows that reference it use the new value from their next request; the old value is discarded.`, confirmLabel: 'Rotate secret' })) return;
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
    <div className="content settings-page">
      <CustomerPageStyles />
      <PageHeader
        route="settings"
        title="Settings"
        eyebrow="Workspace configuration"
        description="Organization name, automation credentials, stored integration secrets, and data retention. Each change is saved and audited on its own."
      />
      <Tabs value={tab} options={settingsTabOptions} onChange={setTab} className="tabs-wrap" ariaLabel="Settings sections"
            getTabId={(id) => `settings-sections-tab-${id}`}
            getPanelId={(id) => `settings-sections-panel-${id}`} />
      {(message || error) && (
        <Toast
          message={error || message}
          tone={error ? 'error' : 'success'}
          duration={5000}
        />
      )}
      {oneTimeSecret && (
        <Card className="secret-card" role="region" aria-label={oneTimeSecret.label}>
          <PanelCardHeader
            title={oneTimeSecret.label}
            description="Shown once. It is not stored in the browser and cannot be retrieved after you dismiss it or leave this page."
            trailing={
              <div className="row-actions">
                <Button variant="ghost" size="sm" aria-pressed={secretRevealed} onClick={() => setSecretRevealed((value) => !value)}>{secretRevealed ? 'Hide' : 'Reveal'}</Button>
                <Button
                  variant="secondary"
                  size="sm"
                  onClick={() => {
                    void navigator.clipboard.writeText(oneTimeSecret.value).then(() => {
                      setMessage('Secret copied. Store it in your secret manager now.');
                      setError('');
                    }).catch(() => {
                      setError('Clipboard copy failed. Reveal the secret and copy it manually.');
                    });
                  }}
                >
                  Copy secret
                </Button>
              </div>
            }
          />
          <CardContent className="stack-tight">
            <pre className="codeblock cp-mono-wrap" aria-label="One-time secret">{secretRevealed ? oneTimeSecret.value : '•'.repeat(Math.min(32, oneTimeSecret.value.length))}</pre>
            <label className="check-row">
              <input type="checkbox" checked={secretAcknowledged} onChange={(event) => setSecretAcknowledged(event.target.checked)} />
              <span>I have stored this secret somewhere safe</span>
            </label>
            <div className="row-actions">
              <Button size="sm" disabled={!secretAcknowledged} onClick={() => { setOneTimeSecret(null); setSecretRevealed(false); setSecretAcknowledged(false); }}>Dismiss secret</Button>
              {!secretAcknowledged ? <span className="muted small">Confirm you stored it before dismissing.</span> : null}
            </div>
          </CardContent>
        </Card>
      )}

      {(
        <div role="tabpanel" id="settings-sections-panel-organization" aria-labelledby="settings-sections-tab-organization" className="tab-panel" hidden={tab !== 'organization'}><>
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
        </div>
        <Card>
          <CardHeader>
            <CardTitle>Users and sign-in</CardTitle>
            <CardDescription>Inviting users, changing roles, and SSO mapping are not self-service in this portal. Ask your deployment administrator.</CardDescription>
          </CardHeader>
          <details className="detail-technical settings-session">
          <summary>Your session details</summary>
          <CardContent className="kv-list">
            <div><span>User ID</span><strong>{session.user_id ?? '—'}</strong></div>
            <div><span>Role</span><strong>{session.role ?? '—'}</strong></div>
            <div><span>Tenant</span><strong>{session.tenant_id ?? data.state?.tenant_id ?? '—'}</strong></div>
            <div><span>Auth mode</span><strong>{config.authMode}</strong></div>
          </CardContent>
          </details>
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

      {(
        <div role="tabpanel" id="settings-sections-panel-access" aria-labelledby="settings-sections-tab-access" className="tab-panel" hidden={tab !== 'access'}><>
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
                    <input name="scopes" defaultValue="tenant:read,evidence:read" spellCheck={false} aria-describedby="sa-scopes-help" />
                    <span className="muted small" id="sa-scopes-help">Comma-separated resource:action permissions. The server rejects scopes the chosen role does not hold.</span>
                  </label>
                  <label>
                    <span>Expiry</span>
                    <select name="expiry" defaultValue="30d">
                      <option value="24h">24 hours</option>
                      <option value="30d">30 days</option>
                      <option value="">No expiry (not recommended)</option>
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

      {(
        <div role="tabpanel" id="settings-sections-panel-security" aria-labelledby="settings-sections-tab-security" className="tab-panel" hidden={tab !== 'security'}><>
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
                <form className="product-form" onSubmit={handleCreateVaultSecret} ref={createVaultFormRef} autoComplete="off">
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
                    <textarea name="plaintext" rows={4} placeholder="Provider access token or JSON credential" required autoComplete="off" spellCheck={false} />
                    <span className="muted small">Cleared when you leave this tab. Never shown again after storing.</span>
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
                <form className="product-form" onSubmit={handleRotateVaultSecret} ref={rotateVaultFormRef} autoComplete="off">
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
                    <textarea name="plaintext" rows={4} placeholder="New provider access token or JSON credential" required autoComplete="off" spellCheck={false} />
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

      {(
        <div role="tabpanel" id="settings-sections-panel-privacy" aria-labelledby="settings-sections-tab-privacy" className="tab-panel" hidden={tab !== 'privacy'}><Card>
          <CardHeader>
            <CardTitle>Privacy and retention</CardTitle>
            <CardDescription>How long each category of data is kept, in days. Shortening a period can delete older records as soon as you save; you review the effect first.</CardDescription>
          </CardHeader>
          <CardContent>
            {canWriteTenant ? (
            <form className="product-form" onSubmit={handleSaveRetention} noValidate>
              <FormNumberField
                label="Metadata retention (days)"
                name="metadata_retention_days"
                min={1}
                max={3650}
                defaultValue={metadataRetentionDays}
                hint={`${recordedMetadataRetentionDays === null ? 'Not recorded; prefilled with the 90-day recommendation. ' : ''}1 to 3650 days. Events, vault metadata, and notification history.`}
              />
              <FormNumberField
                label="Report archive (days)"
                name="report_days"
                min={30}
                max={3650}
                defaultValue={getNumber(evidenceRetention, ['report_days'], 365)}
                hint={`${recordedReportDays === null ? 'Not recorded; prefilled with 365. ' : ''}30 to 3650 days. Generated report snapshots.`}
              />
              <FormNumberField
                label="Audit log retention (days)"
                name="audit_log_days"
                min={365}
                max={3650}
                defaultValue={getNumber(evidenceRetention, ['audit_log_days'], 2555)}
                hint={`${recordedAuditDays === null ? 'Not recorded; prefilled with 2555. ' : ''}365 to 3650 days (2555 is about 7 years). Security audit trail.`}
              />
              <FormNumberField
                label="High-scale artifact retention (days)"
                name="high_scale_artifact_days"
                min={365}
                max={3650}
                defaultValue={getNumber(evidenceRetention, ['high_scale_artifact_days'], 2555)}
                hint={`${recordedHighScaleDays === null ? 'Not recorded; prefilled with 2555. ' : ''}365 to 3650 days. SOC authorization packs.`}
              />
              <label className="check-row full">
                <input name="legal_hold" type="checkbox" defaultChecked={Boolean(evidenceRetention.legal_hold)} />
                <span>Legal hold — block metadata deletions while legal hold is active (read-only boundary for production legal workflows).</span>
              </label>
              {retentionError ? <p className="field-error full" role="alert">{retentionError}</p> : null}
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
        title={retentionReductions.length ? 'Shorten retention?' : 'Save retention settings?'}
        description={(
          <div className="stack-tight">
            <ul className="settings-retention-review">
              {retentionChanges.map((change) => (
                <li key={change.label}>
                  <strong>{change.label}:</strong>{' '}
                  {change.before === null ? `not recorded → ${change.after} days` : change.before === change.after ? `${change.after} days (unchanged)` : `${change.before} → ${change.after} days${change.after < change.before ? ' (shorter)' : ''}`}
                </li>
              ))}
              <li><strong>Legal hold:</strong> {pendingRetention?.evidence_retention.legal_hold ? 'on, deletions are blocked while it stays on' : 'off'}</li>
            </ul>
            {retentionReductions.length ? (
              <p>Records older than the new period{retentionReductions.length > 1 ? 's' : ''} become eligible for deletion. Metadata purge runs as soon as you save{pendingRetention?.evidence_retention.legal_hold ? ', except while legal hold is on' : ''}. Deleted records cannot be recovered.</p>
            ) : <p>No period gets shorter, so nothing becomes newly eligible for deletion.</p>}
            <p className="muted small">Shorter windows can immediately purge stored metadata.</p>
          </div>
        )}
        confirmLabel={retentionReductions.length ? 'Shorten retention' : 'Save retention policy'}
        confirmTone={retentionReductions.length ? 'danger' : 'default'}
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
  const [busy, setBusy] = useState('');
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');
  const [policyTargetIds, setPolicyTargetIds] = useState<string[]>([]);
  const [policyCheckId, setPolicyCheckId] = useState('');
  const [policyCadence, setPolicyCadence] = useState('weekly');
  const [policyExpectedVerdict, setPolicyExpectedVerdict] = useState('pass');
  const [policyTimezone, setPolicyTimezone] = useState('UTC');
  const [policyWindowDay, setPolicyWindowDay] = useState('');
  const [showCreateSchedule, setShowCreateSchedule] = useState(false);
  const [callerPrefill, setCallerPrefill] = useState(() => ({
    checkId: getHashQueryParam('check'),
    targetId: getHashQueryParam('target')
  }));
  const canWritePolicies = sessionHasPermission(session, 'test_policy:write');
  const safeChecks = data.checks.filter((check) => getString(check, ['safety_class']) === 'safe');
  const policyCheckOptions: SelectOption[] = [
    { value: '', label: 'Select check' },
    ...safeChecks.map((check) => ({
      value: getString(check, ['check_id']),
      label: plainCheckName(getString(check, ['name', 'check_id'])),
      description: getString(check, ['check_id'])
    }))
  ];
  const selectedPolicyCheck = safeChecks.find(
    (check) => getString(check, ['check_id', 'id'], '') === policyCheckId
  ) ?? null;
  const activePolicyTargets = data.targets.filter((target) => !target.archived_at && !target.deleted_at);
  const policySelectionReady = policyTargetIds.length > 0 && policyTargetIds.every((id) => {
    const target = activePolicyTargets.find((candidate) => getString(candidate, ['id'], '') === id);
    return target && isPolicyTargetCompatible(selectedPolicyCheck, target);
  });

  // Carry only the caller's exact declared domain; never infer or select other targets.
  useEffect(() => {
    if (!canWritePolicies || !callerPrefill.checkId) return;
    const check = safeChecks.find((candidate) => getString(candidate, ['check_id'], '') === callerPrefill.checkId);
    if (!check) return;
    setPolicyCheckId(callerPrefill.checkId); setShowCreateSchedule(true);
    const target = activePolicyTargets.find((candidate) => getString(candidate, ['id'], '') === callerPrefill.targetId);
    if (target && isPolicyTargetCompatible(check, target)) setPolicyTargetIds([callerPrefill.targetId]);
    setCallerPrefill({ checkId: '', targetId: '' });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [canWritePolicies, callerPrefill.checkId, safeChecks.length, activePolicyTargets.length]);

  function handlePolicyCheckChange(nextCheckId: string) { setPolicyCheckId(nextCheckId); }

  async function handleCreatePolicy(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!canWritePolicies) return;
    const formElement = event.currentTarget;
    const form = new FormData(formElement);
    const checkId = String(form.get('check_id') ?? '').trim();
    if (policyTargetIds.length === 0) {
      setError('Select a declared domain or domains before creating schedules.');
      return;
    }
    if (!policySelectionReady) {
      setError('Select active domains compatible with this check before creating schedules.');
      return;
    }
    if (!checkId) {
      setError('Select a check from the catalog before creating a schedule.');
      return;
    }

    const cadence = String(form.get('cadence') ?? 'manual').trim();
    const timezone = String(form.get('timezone') ?? '').trim() || 'UTC';
    if (!isValidTimezone(timezone)) {
      setError(`"${timezone}" is not a recognised IANA timezone.`);
      return;
    }

    const day = String(form.get('safe_window_day') ?? '').trim();
    const start = String(form.get('safe_window_start') ?? '').trim();
    const end = String(form.get('safe_window_end') ?? '').trim();
    const safeWindowValues = [day, start, end, timezone];
    const hasSafeWindow = [day, start, end].some(Boolean);
    if (hasSafeWindow && !safeWindowValues.every(Boolean)) {
      setError('Complete the safe-window day, start, and end, or leave all three blank.');
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
      timezone,
      expected_verdict: String(form.get('expected_verdict') ?? 'pass'),
      safe_windows
    };
    setBusy('create-test-policy');
    setError('');
    setMessage('');
    try {
      const successes: Array<{ targetId: string; result: unknown }> = [];
      const failures: Array<{ targetId: string; message: string }> = [];
      for (const targetId of policyTargetIds) {
        try {
          const result = await requestJson(config, session, '/v1/test-policies', {
            method: 'POST',
            body: { ...bodyBase, target_id: targetId }
          });
          successes.push({ targetId, result });
        } catch (err) {
          failures.push({
            targetId,
            message: apiErrorMessage(err, 'Schedule creation failed.')
          });
        }
      }

      let refreshFailure = '';
      if (successes.length > 0) {
        try {
          await onRefresh();
        } catch (err) {
          refreshFailure = apiErrorMessage(err, 'The schedule list could not be refreshed.');
        }
      }

      if (failures.length > 0) {
        const failedIds = new Set(failures.map((failure) => failure.targetId));
        setPolicyTargetIds([...failedIds]);
        const failedResults = failures
          .map((failure) => `${targetDisplayName(data, failure.targetId)}: ${failure.message}`)
          .join(' ');
        setError(
          `Created ${successes.length} of ${policyTargetIds.length} policies. `
          + `Failed ${failures.length}: ${failedResults} `
          + 'Successful writes were retained; only failed exact target bindings remain selected for retry.'
          + (refreshFailure ? ` ${refreshFailure}` : '')
        );
        return;
      }

      const lastResult = successes.at(-1)?.result ?? null;
      const success = `Created ${successes.length} validation ${successes.length === 1 ? 'schedule' : 'schedules'}. The scheduler recorded each first run time shown in the list.`;
      if (refreshFailure) {
        setPolicyTargetIds([]);
        formElement.reset();
        setError(`${success} ${refreshFailure} The writes succeeded; refresh the page instead of creating them again.`);
        return;
      }
      setMessage(formatMutationSuccessMessage(success, lastResult));
      setPolicyTargetIds([]);
      setPolicyWindowDay('');
      formElement.reset();
      setShowCreateSchedule(false);
    } finally {
      setBusy('');
    }
  }

  const refinedProps: PoliciesRefinedProps = {
    data,
    config,
    session,
    onRefresh,
    busy,
    message,
    error,
    canWritePolicies,
    safeChecks,
    onCreateSchedule: () => {
      setError('');
      setMessage('');
      if (!policyCheckId && safeChecks.length === 1) setPolicyCheckId(getString(safeChecks[0], ['check_id'], ''));
      setShowCreateSchedule(true);
    },
    onActionResult: (nextMessage, nextError) => {
      setMessage(nextMessage);
      setError(nextError);
    },
    createForm: {
      open: canWritePolicies && showCreateSchedule,
      onClose: () => setShowCreateSchedule(false),
      onSubmit: (event) => void handleCreatePolicy(event),
      targets: activePolicyTargets,
      selectedTargetIds: policyTargetIds,
      onTargetsChange: setPolicyTargetIds,
      selectionReady: policySelectionReady,
      selectedCheck: selectedPolicyCheck,
      checkId: policyCheckId,
      checkOptions: policyCheckOptions,
      onCheckChange: handlePolicyCheckChange,
      cadence: policyCadence,
      cadenceOptions: POLICY_CADENCE_OPTIONS,
      onCadenceChange: setPolicyCadence,
      expectedVerdict: policyExpectedVerdict,
      verdictOptions: POLICY_VERDICT_OPTIONS,
      onExpectedVerdictChange: setPolicyExpectedVerdict,
      timezone: policyTimezone,
      onTimezoneChange: setPolicyTimezone,
      windowDay: policyWindowDay,
      onWindowDayChange: setPolicyWindowDay
    }
  };
  return <PoliciesRefined {...refinedProps} />;
}

export function SupportPage({ data, session, config }: { data: PortalData; session: Session; config: PortalConfig }) {
  const summary = data.subscriptionSummary;
  const supportUri = configuredSupportUri(config.siteConfig);
  const support = getNestedItem(summary, ['support']);
  const usage = getNestedItem(summary, ['usage']);
  const account = getNestedItem(summary, ['account']);
  const recentAudit = getNestedArray(support, ['recent_audit']);
  const openFindings = getOptionalNumber(usage, ['open_findings']);
  const supportOwner = getString(support ?? {}, ['owner'], '');
  const supportLoadError = data.loadErrors.subscriptionSummary;
  const routeAccessContext = { principal: session.principal, staffRole: session.staff_role };
  const role = session.role ?? '';
  const canReadAuditEvents = canAccessRoute(role, 'audit', routeAccessContext) && ['owner', 'admin', 'soc', 'auditor'].includes(role);
  const canReadNotifications = canAccessRoute(role, 'notifications', routeAccessContext);
  const snapshotAt = getString(support ?? {}, ['as_of'], '') || getString(summary ?? {}, ['as_of', 'generated_at'], '');
  const snapshotSource = getString(support ?? {}, ['as_of_source'], '') || getString(summary ?? {}, ['as_of_source'], '');
  const [loadedAt] = useState(() => new Date().toISOString());
  const [draftNote, setDraftNote] = useState('');
  const [includedRefs, setIncludedRefs] = useState<Record<string, boolean>>({});
  const [copyState, setCopyState] = useState<{ tone: 'ok' | 'error'; text: string } | null>(null);
  const contactLabel = supportUri.startsWith('mailto:') ? supportUri.slice('mailto:'.length).split('?')[0] : supportUri;
  const tenantId = session.tenant_id ?? getString(account ?? {}, ['tenant_id'], '');

  const references = recentAudit.slice(0, 10).map((entry) => ({
    id: getString(entry, ['id'], ''),
    action: getString(entry, ['action'], ''),
    resourceType: getString(entry, ['resource_type'], ''),
    resourceId: getString(entry, ['resource_id'], ''),
    at: getString(entry, ['timestamp'], '') || getString(entry, ['created_at'], ''),
    atSource: getString(entry, ['timestamp_source'], '') || (getString(entry, ['timestamp'], '') ? 'audit_log.timestamp' : getString(entry, ['created_at'], '') ? 'audit_log.created_at_alias' : 'not_recorded')
  })).filter((entry) => entry.id);

  function buildSummary() {
    const chosen = references.filter((ref) => includedRefs[ref.id]);
    const note = draftNote.replace(/\s+/g, ' ').trim().slice(0, 1000);
    return [
      'AstraNull investigation summary (references only)',
      `Workspace: ${tenantId || 'not recorded'}`,
      `Prepared: ${new Date().toISOString()} by ${session.user_id ?? 'unknown user'} (${role || 'role not recorded'})`,
      `Open findings in account snapshot: ${openFindings === null ? 'not recorded' : openFindings} (as of ${snapshotAt || 'snapshot time not provided'})`,
      chosen.length
        ? `Audit events:\n${chosen.map((ref) => `- ${ref.id} · ${ref.action} · ${ref.resourceType}${ref.resourceId ? ` ${ref.resourceId}` : ''} · ${ref.at && ref.atSource !== 'not_recorded' ? `${ref.at}${ref.atSource === 'audit_log.created_at_alias' ? ' (legacy created_at)' : ''}` : 'time not recorded'}`).join('\n')}`
        : 'Audit events: none selected',
      `Notes: ${note || 'none'}`,
      'Contains identifiers only. No credentials, tokens, payloads, or evidence content are included.'
    ].join('\n');
  }

  async function copySummary() {
    const text = buildSummary();
    if (/(bearer\s+[a-z0-9._-]+|password\s*[:=]|secret\s*[:=]|api[_-]?key\s*[:=])/i.test(draftNote)) {
      setCopyState({ tone: 'error', text: 'Your note looks like it contains a credential. Remove it before copying; rotate it if it was real.' });
      return;
    }
    try {
      await navigator.clipboard.writeText(text);
      setCopyState({ tone: 'ok', text: 'Summary copied. Nothing was sent; paste it into your support channel.' });
    } catch {
      setCopyState({ tone: 'error', text: 'Clipboard unavailable. Select the preview text and copy it manually.' });
    }
  }

  return (
    <div className="content support-page">
      <CustomerPageStyles />
      <PageHeader
        route="support"
        title="Support"
        eyebrow="Escalation and references"
        description="Prepare a reference-only summary for your support contact and open the exact events behind it. AstraNull does not send anything from this page."
        actions={supportUri ? <AnchorButton href={supportUri} variant="default" size="sm">Contact support</AnchorButton> : undefined}
      />
      {supportLoadError ? (
        <div className="form-banner error row-actions" role="alert">
          <span>Account support details could not be loaded: {supportLoadError}</span>
          <Button type="button" size="sm" variant="secondary" onClick={() => window.location.reload()}>Retry</Button>
        </div>
      ) : null}
      <div className="split">
        <Card>
          <PanelCardHeader title="Who to contact" description="Only configured channels are shown. No response time is promised here." />
          <CardContent className="stack-tight">
            {supportUri ? (
              <p className="cp-note">Support channel configured for this deployment: <a className="cp-link" href={supportUri}>{contactLabel}</a>. Opening it uses your own mail client or browser; nothing is sent automatically.</p>
            ) : (
              <div className="form-banner neutral" role="status">
                No support channel is configured for this deployment. Contact your workspace administrator{supportOwner ? ` or the recorded support owner (${supportOwner})` : ''} and share the summary below.
              </div>
            )}
            <div className="kv-list">
              <div><span>Support owner</span><strong>{supportOwner || 'Not assigned'}</strong></div>
              <div><span>Account state</span><strong>{getString(account ?? support ?? {}, ['lifecycle_state'], 'Not recorded').replaceAll('_', ' ')}</strong></div>
              <div><span>Region</span><strong>{getString(account ?? support ?? {}, ['region'], 'Not recorded')}</strong></div>
              <div><span>Response coverage</span><strong>{getString(support ?? {}, ['coverage', 'support_hours'], 'Not recorded')}</strong></div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <PanelCardHeader
            title="Account snapshot"
            description={snapshotAt ? `From the account summary as of ${formatDate(snapshotAt)}${snapshotSource === 'subscription_summary_clock' ? ' (server read time)' : ''}. Counts are workspace-wide and may differ from filtered pages.` : `From the account summary loaded ${formatDate(loadedAt)}; the summary has no snapshot time.`}
          />
          <CardContent className="kv-list">
            <div><span>Open findings, whole workspace (snapshot)</span><strong>{summary ? (openFindings === null ? 'Not recorded' : formatNumber(openFindings)) : 'Unavailable'}</strong></div>
            <div><span>Live findings</span><strong><a className="cp-link" href="#findings">Open findings list</a></strong></div>
            {canReadNotifications ? <div><span>Alert routing</span><strong><a className="cp-link" href="#notifications">Notifications</a></strong></div> : null}
          </CardContent>
        </Card>
      </div>
      <Card>
        <PanelCardHeader title="Recent events" description={canReadAuditEvents ? 'Select events to include in the summary. View opens that exact event in the audit log.' : 'Event references can be included. Opening the audit log needs an owner, admin, SOC, or auditor role.'} />
        <CardContent>
          {recentAudit.length === 0 ? (
            <EmptyState icon={FileCheck2} title="No recent events in the account summary." body="Events appear here after security-relevant actions are recorded." />
          ) : (
            <ul className="support-event-list">
              {references.map((ref) => (
                <li key={ref.id} className="support-event-row">
                  <label className="check-row">
                    <input
                      type="checkbox"
                      checked={Boolean(includedRefs[ref.id])}
                      onChange={(event) => setIncludedRefs((current) => ({ ...current, [ref.id]: event.target.checked }))}
                    />
                    <span className="cp-stack">
                      <span>{formatAuditAction(ref.action, ref.action)} <span className="muted">· {formatResourceTypeLabel(ref.resourceType || 'audit')}</span></span>
                      <span className="muted small mono">{ref.id} · {ref.at && ref.atSource !== 'not_recorded' ? `${formatDate(ref.at)}${ref.atSource === 'audit_log.created_at_alias' ? ' (legacy time field)' : ''}` : 'Time not recorded'}</span>
                    </span>
                  </label>
                  {canReadAuditEvents ? (
                    <AnchorButton size="sm" variant="ghost" href={`#audit?event=${encodeURIComponent(ref.id)}`} aria-label={`View audit event ${ref.id}`}>View event</AnchorButton>
                  ) : null}
                </li>
              ))}
            </ul>
          )}
        </CardContent>
      </Card>
      <Card>
        <PanelCardHeader title="Investigation summary" description="Copy-only. References and your note; no credentials, payloads, or evidence content." />
        <CardContent className="stack-tight">
          <label className="field full">
            <span>Your note (optional)</span>
            <textarea
              rows={3}
              maxLength={1000}
              value={draftNote}
              onChange={(event) => { setDraftNote(event.target.value); setCopyState(null); }}
              placeholder="What you observed and what you need. Do not paste secrets."
            />
          </label>
          <pre className="codeblock support-summary-preview" tabIndex={0} aria-label="Summary preview">{buildSummary()}</pre>
          <div className="row-actions">
            <Button size="sm" onClick={() => void copySummary()}>Copy summary</Button>
            {copyState ? <span className={copyState.tone === 'error' ? 'field-error' : 'muted small'} role={copyState.tone === 'error' ? 'alert' : 'status'}>{copyState.text}</span> : null}
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
  connectors: 'Provider connectors',
  high_scale_program: 'High-scale program (SOC-governed)'
};

const ENTITLEMENT_FEATURE_NOTES: Record<(typeof ENTITLEMENT_FEATURES)[number], string> = {
  waf_posture: 'Not that any WAF is detected or protecting a target; that comes from check evidence.',
  external_discovery: 'Not that inventory is discovered automatically; targets stay customer-declared.',
  connectors: 'Not that a provider is connected; set one up in Integrations.',
  high_scale_program: 'Not self-service. Only SOC can approve and run high-scale validation.'
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

export function SubscriptionPage({ data, config }: { data: PortalData; config?: PortalConfig }) {
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
  const usersLimit = getNestedNumber(subscription, ['limits', 'users'], -1);
  const usersUsed = readUsage('users');
  const openFindings = readUsage('open_findings');
  const supportUri = config ? configuredSupportUri(config.siteConfig) : '';
  const subscriptionStatus = getString(subscription ?? {}, ['status'], 'unrecorded');
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
    { label: 'Bounded checks started', description: 'Unit: checks · window: last 60 minutes', used: safeRunsUsed, limit: safeRunsLimit },
    { label: 'Users', description: 'Unit: workspace members · current count', used: usersUsed, limit: usersLimit }
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
      label: 'Access',
      render: (item) => (
        <SubscriptionEntitlementIndicator value={item.effective_enabled} enabledLabel="Available" disabledLabel="Unavailable" />
      )
    },
    {
      key: 'why',
      label: 'Why',
      render: (item) => {
        const source = formatEntitlementGrantSource(getString(item, ['grant_source'], 'not recorded'));
        const plan = item.plan_enabled === true ? 'Included in plan' : item.plan_enabled === false ? 'Not in plan' : 'Plan inclusion not recorded';
        return <span className="cp-stack"><span>{plan}</span><span className="muted small">Source: {source}</span></span>;
      }
    },
    {
      key: 'means',
      label: 'What access does not mean',
      render: (item) => <span className="muted small">{ENTITLEMENT_FEATURE_NOTES[getString(item, ['feature']) as (typeof ENTITLEMENT_FEATURES)[number]] ?? 'Access alone does not configure or validate anything.'}</span>
    }
  ];
  const refreshPage = () => window.location.reload();

  if (subscriptionLoadError) {
    return (
      <div className="content subscription-page">
        <style>{SUBSCRIPTION_PAGE_STYLES}</style>
        <PageHeader route="subscription" title="Plan & usage" eyebrow="Account" />
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
        <PageHeader route="subscription" title="Plan & usage" eyebrow="Account" />
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
          title="Plan & usage"
          eyebrow="Account"
          actions={<Button type="button" variant="secondary" size="sm" onClick={refreshPage}><RefreshCw size={15} aria-hidden="true" /> Refresh</Button>}
        />
        <EmptyState
          icon={LifeBuoy}
          title="No subscription configured for this tenant."
          body="No subscription record is available. Limits and feature access are unknown, not unlimited. Ask your workspace administrator or support contact to provision one."
          actionLabel="Open support"
          actionHref="#support"
        />
      </div>
    );
  }

  return (
    <div className="content subscription-page">
      <style>{SUBSCRIPTION_PAGE_STYLES}</style>
      <PageHeader
        route="subscription"
        title="Plan & usage"
        eyebrow="Account"
        description="Your recorded plan, measured usage against its limits, and which features your plan makes available. This page has no billing or payment actions."
      />
      <div className="subscription-toolbar" role="status" aria-live="polite">
        <span className="subscription-freshness"><Activity size={14} aria-hidden="true" /> {freshnessLabel}</span>
        <Button type="button" variant="secondary" size="sm" onClick={refreshPage} title="Reload the page to request a fresh subscription snapshot.">
          <RefreshCw size={15} aria-hidden="true" /> Refresh
        </Button>
      </div>
      <PageContextSummary>
        {planLabel} · bounded checks{' '}
        <span className="tabular-nums">
          {safeRunsUsed === null ? 'not measured' : `${safeRunsUsed}${safeRunsLimit >= 0 ? ` of ${safeRunsLimit}` : ', limit not recorded'}`}
        </span>{' '}
        in the last 60 minutes
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
              <dd>{subscription?.renewal_at ? formatDate(subscription.renewal_at) : 'Not recorded'}</dd>
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
                        <strong>{hasUsage ? formatNumber(row.used!) : 'Not measured'}</strong>
                        <span>{hasUsage ? (hasLimit ? `of ${formatNumber(row.limit)} allowed` : 'used · limit not recorded (not unlimited)') : hasLimit ? `Limit ${formatNumber(row.limit)} · usage not measured (not zero)` : 'Usage and limit not recorded'}</span>
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
              <div className="subscription-signal-strip" aria-label="Workspace signal that is not a plan limit">
                <strong>Not a plan limit</strong>
                <span className="subscription-signal-item">Open findings in this snapshot <Badge tone="muted">{openFindings === null ? 'Not recorded' : formatNumber(openFindings)}</Badge></span>
              </div>
            </>
          ) : (
            <EmptyState icon={Activity} title="No usage snapshot recorded." body="Plan details are available, but workspace usage counts were not recorded." />
          )}
        </CardContent>
      </Card>

      <Card className="card--dense">
        <PanelCardHeader
          title="Feature access"
          description="Whether your plan lets you use a feature. Available does not mean it is configured or working."
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
            empty={<EmptyState icon={ShieldCheck} title="No feature definitions." body="The plan did not return any recognized features." />}
          />
        </CardContent>
      </Card>
      <Card className="card--dense">
        <PanelCardHeader title="Change your plan or limits" description="Plan changes are handled outside the portal." />
        <CardContent className="row-actions">
          {supportUri
            ? <AnchorButton href={supportUri} variant="secondary" size="sm">Contact support</AnchorButton>
            : <span className="muted small">No support channel is configured. Ask your workspace administrator{getString(account ?? {}, ['contract_reference'], '') ? ` and quote contract reference ${getString(account ?? {}, ['contract_reference'], '')}` : ''}.</span>}
          <AnchorButton href="#support" variant="ghost" size="sm">Prepare a support summary</AnchorButton>
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
      {(message || error) && (
        <Toast
          message={error || message}
          tone={error ? 'error' : 'success'}
          duration={5000}
        />
      )}
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
