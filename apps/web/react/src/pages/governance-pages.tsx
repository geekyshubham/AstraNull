import { useEffect, useMemo, useRef, useState, type FormEvent, type ReactNode } from 'react';
import { Activity, Bell, CheckCircle2, ClipboardList, Copy, FileText, Info, Lock, Search, ShieldCheck, Siren, Users } from 'lucide-react';
import { Badge } from '../components/ui/badge';
import { AnchorButton, Button } from '../components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../components/ui/card';
import { EmptyState } from '../components/ui/empty-state';
import { Select } from '../components/ui/select';
import { DataTable, type TableColumn } from '../components/ui/table';
import { fetchPortalConfig, isStaffSocRole, requestJson, requestSocJson, saveSession } from '../lib/api';
import {
  computeReleaseEvidenceCoverage,
  pickReleaseEvidenceCustodyUri,
  summarizeReleaseEvidenceValidation
} from '../lib/release-evidence';
import {
  buildLifecycleTimeline,
  governedLimitDisplay,
  providerApprovalRequired,
  requestDomainDisplay,
  scheduledWindowState
} from '../lib/high-scale';
import { isFindingOpen } from '../lib/finding-lifecycle.mjs';
import type { DataItem, PortalConfig, PortalData, Session } from '../lib/types';
import { buildDetailHref, getRouteTenantId, parseInspectorRef, replaceRouteParams } from '../lib/route-params';
import { apiErrorMessage } from '../lib/error-messages';
import {
  AUDIT_ACTION_LABELS,
  AUDIT_ACTIONS,
  RESOURCE_TYPE_LABELS,
  formatAuditAction,
  formatDate,
  formatNumber,
  formatResourceTypeLabel,
  pluralize,
  sensitiveResourceLabel,
  tailTruncateId
} from '../lib/utils';
import { prefersReducedMotion } from '../lib/motion';
// @ts-ignore Plain ESM keeps machine-code labels directly testable with node:test.
import { plainCodeLabel } from '../lib/plain-language.mjs';
import { CustomerPageStyles, KpiCell, PageContextSummary, PageHeader, PanelCardHeader } from './page-components';
import { useConfirmModal } from '../lib/crud-ui';
import { PortalLoadingSkeleton } from '../lib/empty-from-api';
import { highScaleStateTone } from '../lib/status-tone';
import {
  DEFAULT_NOTIFICATION_TRIGGERS,
  NOTIFICATION_TRIGGER_OPTIONS,
  notificationChannelLabel,
  notificationTriggerLabel
} from '../lib/notification-channels.mjs';

function getString(item: DataItem | null | undefined, keys: string[], fallback = '—') {
  if (!item) return fallback;
  for (const key of keys) {
    const value = item[key];
    if (value !== undefined && value !== null && value !== '') return String(value);
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

function getNestedString(item: DataItem | null | undefined, path: string[], fallback = '—') {
  let current: unknown = item;
  for (const key of path) {
    if (!current || typeof current !== 'object' || Array.isArray(current)) return fallback;
    current = (current as DataItem)[key];
  }
  if (current !== undefined && current !== null && current !== '') return String(current);
  return fallback;
}

function isFlatMetadataObject(value: unknown): value is Record<string, string | number | boolean | null> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  return Object.values(value).every(
    (entry) => entry === null || ['string', 'number', 'boolean'].includes(typeof entry)
  );
}

function auditEntrySelectionKey(item: DataItem) {
  const id = getString(item, ['id', 'audit_id'], '');
  if (id) return id;
  return [
    getString(item, ['created_at'], ''),
    getString(item, ['action'], ''),
    getString(item, ['resource_type'], ''),
    getString(item, ['resource_id'], '')
  ].join('::');
}

function downloadJsonFile(filename: string, payload: unknown) {
  const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = filename;
  anchor.click();
  URL.revokeObjectURL(url);
}

function killSwitchIdList(item: DataItem, key: 'stopped_request_ids' | 'cancelled_run_ids') {
  const value = item[key];
  return Array.isArray(value) ? value.map(String).filter(Boolean) : [];
}

function summarizeSocActionPayload(payload: unknown) {
  if (!payload || typeof payload !== 'object') return 'Action completed successfully.';
  const item = payload as DataItem;
  if ('active' in item) {
    if (!item.active) return 'Kill switch cleared; governed runs may resume when approved.';
    const stopped = killSwitchIdList(item, 'stopped_request_ids').length;
    const cancelled = killSwitchIdList(item, 'cancelled_run_ids').length;
    const operator = getString(item, ['updated_by'], 'an unrecorded operator');
    const at = item.updated_at ? formatDate(item.updated_at) : 'an unrecorded time';
    return `Kill switch engaged by ${operator} at ${at}. Stopped ${formatNumber(stopped)} high-scale ${pluralize(stopped, 'request')}, cancelled ${formatNumber(cancelled)} safe ${pluralize(cancelled, 'run')}.`;
  }
  const adapterState = getNestedString(item, ['adapter', 'state'], '');
  if (adapterState && adapterState !== '—') {
    const traffic = getNestedString(item, ['adapter', 'traffic_generated'], 'false');
    return `Adapter status: ${adapterState}${traffic === 'true' ? ', traffic generation reported' : ', no traffic generation reported'}.`;
  }
  const requestState = getString(item, ['state'], '');
  if (requestState && requestState !== '—') return `High-scale request updated — current state is ${requestState}.`;
  const reportId = getString(item, ['id'], '');
  if (reportId && reportId !== '—' && getString(item, ['high_scale_request_id'], '') !== '—') {
    return `Post-test report saved (${reportId}).`;
  }
  return 'SOC action completed successfully.';
}

function canWriteNotifications(role: string | undefined) {
  return role === 'admin' || role === 'owner';
}

function canReadAudit(role: string | undefined) {
  return ['admin', 'owner', 'soc', 'auditor'].includes(String(role ?? ''));
}

function canReadReleaseEvidence(role: string | undefined) {
  return ['admin', 'owner', 'soc', 'auditor'].includes(String(role ?? ''));
}

type GovernanceBadgeTone = 'default' | 'success' | 'warn' | 'danger' | 'info' | 'muted';


function authorizationPackBadgeTone(overall: string): GovernanceBadgeTone {
  const normalized = overall.trim().toLowerCase();
  if (normalized === 'accepted') return 'success';
  if (normalized === 'missing' || normalized === '—' || !normalized) return 'muted';
  return 'warn';
}

function releaseEvidenceStatusBadgeTone(status: string): GovernanceBadgeTone {
  const normalized = status.trim().toLowerCase();
  if (['accepted', 'valid', 'passed', 'recorded'].includes(normalized)) return 'success';
  if (['failed', 'rejected', 'invalid'].includes(normalized)) return 'danger';
  if (['pending', 'review', 'unknown'].includes(normalized)) return 'warn';
  return 'muted';
}

function productionReadyBadgeTone(value: unknown): GovernanceBadgeTone {
  if (value === true) return 'success';
  if (value === false) return 'warn';
  return 'muted';
}

function productionReadyLabel(value: unknown) {
  if (value === true) return 'Ready';
  if (value === false) return 'Not ready';
  return 'Unknown';
}

function formatGovernanceStatusLabel(value: string, fallback = '—') {
  const trimmed = value.trim();
  if (!trimmed || trimmed === '—') return fallback;
  return plainCodeLabel(trimmed, fallback);
}

function authorizationPackLabel(overall: string) {
  const normalized = overall.trim().toLowerCase();
  if (normalized === 'accepted') return 'Accepted';
  if (normalized === 'missing' || !normalized) return 'Missing';
  return formatGovernanceStatusLabel(overall);
}

function authorizationPackSummary(item: DataItem) {
  const status = getNestedItem(item, ['authorization_pack_status']);
  const overall = getString(status, ['overall'], 'missing');
  const requirements = Array.isArray(status?.requirements) ? status.requirements as DataItem[] : [];
  const accepted = requirements.filter((requirement) => getString(requirement, ['status'], '').toLowerCase() === 'accepted').length;
  return {
    overall,
    label: requirements.length > 0 && overall.toLowerCase() !== 'accepted'
      ? `${formatNumber(accepted)}/${formatNumber(requirements.length)} accepted`
      : authorizationPackLabel(overall),
    detail: requirements.length > 0
      ? `${formatNumber(accepted)} of ${formatNumber(requirements.length)} required artifacts accepted`
      : `Authorization pack status: ${authorizationPackLabel(overall)}`
  };
}

function providerApprovalSummary(item: DataItem): { label: string; detail: string; tone: GovernanceBadgeTone } {
  if (!providerApprovalRequired(item)) {
    return { label: 'Not required', detail: 'No provider approval requirement declared', tone: 'muted' };
  }
  const checklist = Array.isArray(item.provider_approval_checklist)
    ? (item.provider_approval_checklist as DataItem[]).filter((entry) => entry.required !== false)
    : [];
  if (checklist.length === 0) {
    return { label: 'Missing', detail: 'Provider approval evidence has not been attached', tone: 'warn' };
  }
  const statuses = checklist.map((entry) => getString(entry, ['status'], 'missing').toLowerCase());
  const providerNames = checklist
    .map((entry) => getString(entry, ['provider_name'], ''))
    .filter((name) => name && name !== '—')
    .join(', ');
  if (statuses.every((status) => status === 'accepted')) {
    return { label: 'Accepted', detail: providerNames || 'All required provider approvals accepted', tone: 'success' };
  }
  const blocking = statuses.find((status) => ['rejected', 'expired'].includes(status));
  if (blocking) {
    return { label: formatGovernanceStatusLabel(blocking), detail: providerNames || 'Provider approval requires attention', tone: 'danger' };
  }
  const pending = statuses.find((status) => status !== 'accepted') ?? 'pending';
  return { label: formatGovernanceStatusLabel(pending), detail: providerNames || 'Provider approval is not yet accepted', tone: 'warn' };
}

function notificationOperationDisabledReason(
  canWrite: boolean,
  busy: string,
  ownBusyLabel: string,
  needsDlq: boolean,
  dlqCount: number
) {
  if (!canWrite) return 'Owner or admin role is required for delivery operations.';
  if (needsDlq && dlqCount === 0) return 'No dead-letter attempts are available to preview or redrive.';
  if (busy && busy !== ownBusyLabel) return 'Another notification action is in progress.';
  return '';
}

function GovernanceFeedbackBanner({ message, error, children }: { message: string; error: string; children?: ReactNode }) {
  if (!message && !error) return null;
  return (
    <div
      className={error ? 'form-banner error' : 'form-banner'}
      role={error ? 'alert' : 'status'}
      aria-live="polite"
    >
      {error || message}
      {!error && children ? children : null}
    </div>
  );
}

function GovernanceInfoBanner({ children }: { children: ReactNode }) {
  return (
    <div className="form-banner info" role="status" aria-live="polite">
      {children}
    </div>
  );
}

function DeliveryOperationPanel({
  titleId,
  title,
  description,
  note,
  noteId,
  children
}: {
  titleId: string;
  title: string;
  description: string;
  note?: string;
  noteId?: string;
  children: ReactNode;
}) {
  return (
    <section className="operation-panel" aria-labelledby={titleId}>
      <div>
        <h3 id={titleId}>{title}</h3>
        <p>{description}</p>
      </div>
      <div className="row-actions">{children}</div>
      {note ? <p className="muted small" id={noteId}>{note}</p> : null}
    </section>
  );
}

function KvField({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div>
      <span>{label}</span>
      <strong>{children}</strong>
    </div>
  );
}

function KillSwitchReadOnlyCard({ active, reason }: { active: boolean; reason: string }) {
  return (
    <Card density="compact">
      <CardHeader>
        <CardTitle>Kill switch</CardTitle>
        <CardDescription>Read-only tenant emergency-stop status. Activation and clearance require an SOC role.</CardDescription>
      </CardHeader>
      <CardContent className="kv-list">
        <KvField label="Status">
          <Badge tone={active ? 'danger' : 'success'}>{active ? 'Active' : 'Clear'}</Badge>
        </KvField>
        <KvField label="Reason">{reason || <span className="muted">Not recorded</span>}</KvField>
      </CardContent>
    </Card>
  );
}

function ExpandableCodePanel({
  panelId,
  expanded,
  onToggle,
  toggleLabels,
  code,
  truncated,
  downloadLabel,
  onDownload
}: {
  panelId: string;
  expanded: boolean;
  onToggle: () => void;
  toggleLabels: { show: string; hide: string };
  code: string;
  truncated?: boolean;
  downloadLabel?: string;
  onDownload?: () => void;
}) {
  return (
    <div className="full">
      <div className="row-actions">
        <Button
          size="sm"
          variant="ghost"
          aria-expanded={expanded}
          aria-controls={panelId}
          onClick={onToggle}
        >
          {expanded ? toggleLabels.hide : toggleLabels.show}
        </Button>
        {truncated && onDownload && downloadLabel ? (
          <Button size="sm" variant="secondary" onClick={onDownload}>
            {downloadLabel}
          </Button>
        ) : null}
      </div>
      {expanded ? (
        <div className="stack-tight full" id={panelId}>
          <pre className="codeblock" tabIndex={0} role="region" aria-label="Technical metadata JSON, scrollable">{code}</pre>
          {truncated ? <Badge tone="warn">Truncated — download for full JSON</Badge> : null}
        </div>
      ) : null}
    </div>
  );
}

function TableQueueSkeleton({ rows = 2 }: { rows?: number }) {
  return (
    <div className="stack-tight" role="status" aria-live="polite" aria-label="Loading queue">
      {Array.from({ length: rows }, (_, index) => (
        <span key={index} className="skeleton skeleton-row" />
      ))}
    </div>
  );
}

const SOC_SCHEDULED_STATES = ['scheduled', 'approved'];
const SOC_REVIEW_STATES = ['submitted', 'under_review', 'pending', 'draft'];
const SOC_RUNNING_STATES = ['running', 'executing', 'active', 'started'];

const SOC_TERMINAL_STATES = ['closed', 'stopped', 'rejected', 'cancelled', 'completed'];

// Mirrors KILL_SWITCH_REQUIRED_STEP_IDS in src/contracts/killSwitchValidation.mjs.
const KILL_SWITCH_SEQUENCE = [
  'activate_tenant_kill_switch',
  'block_new_safe_runs',
  'cancel_active_safe_runs',
  'probe_fleet_stops_leasing',
  'adapter_stop_path_invoked',
  'audit_timeline_recorded',
  'clear_and_resume_guarded'
] as const;

const KILL_SWITCH_STEP_LABELS: Record<(typeof KILL_SWITCH_SEQUENCE)[number], string> = {
  activate_tenant_kill_switch: 'Arm tenant kill switch',
  block_new_safe_runs: 'Block new safe runs',
  cancel_active_safe_runs: 'Cancel active safe runs',
  probe_fleet_stops_leasing: 'Probe fleet stops leasing work',
  adapter_stop_path_invoked: 'Invoke execution adapter stop',
  audit_timeline_recorded: 'Record audit timeline',
  clear_and_resume_guarded: 'Clear and resume behind safety gates'
};

const KILL_SWITCH_REASON_MIN = 8;
const KILL_SWITCH_REASON_MAX = 280;

function normalizeHighScaleState(item: DataItem) {
  return getString(item, ['state'], '').trim().toLowerCase();
}

type SocGoNoGoGate = { key: string; label: string; tone: GovernanceBadgeTone; status: string };

const SOC_GATE_LABEL = {
  packs: 'Authorization packs',
  providers: 'Provider approvals',
  kill: 'Tenant kill switch',
  execution: 'Running governed tests',
  findings: 'Open findings'
} as const;

const SOC_VERDICT_GATE_KEYS = ['kill', 'packs', 'providers'];

function socGoNoGoVerdict(gates: SocGoNoGoGate[]): { tone: GovernanceBadgeTone; label: string } {
  const blocking = gates.filter((gate) => SOC_VERDICT_GATE_KEYS.includes(gate.key) && (gate.tone === 'danger' || gate.tone === 'warn'));
  if (blocking.length === 0) return { tone: 'success', label: 'Go for scheduled requests' };
  const reasons = blocking.map((gate) => `${gate.label.toLowerCase()} ${gate.status.toLowerCase()}`).join(', ');
  return { tone: blocking.some((gate) => gate.tone === 'danger') ? 'danger' : 'warn', label: `No-Go · ${reasons}` };
}

const SOC_GO_NO_GO_LABELS = Object.entries(SOC_GATE_LABEL).map(([key, label]) => ({ key, label }));

function socPackGate(actionableCount: number, pendingCount: number): { tone: GovernanceBadgeTone; status: string } {
  if (actionableCount === 0) return { tone: 'muted', status: 'No open requests' };
  if (pendingCount === 0) return { tone: 'success', status: 'All accepted' };
  return { tone: 'warn', status: `${formatNumber(pendingCount)} pending` };
}

function buildSocGoNoGoGates(
  requests: DataItem[],
  context: { killSwitchActive: boolean; runningCount: number; openFindings: number; tenantSelected: boolean }
): SocGoNoGoGate[] {
  if (!context.tenantSelected) {
    return SOC_GO_NO_GO_LABELS.map(({ key, label }) => ({ key, label, tone: 'muted', status: 'Tenant not selected' }));
  }
  const actionable = requests.filter((item) =>
    [...SOC_REVIEW_STATES, ...SOC_SCHEDULED_STATES].includes(normalizeHighScaleState(item))
  );
  const packAccepted = actionable.filter(
    (item) => getNestedString(item, ['authorization_pack_status', 'overall'], 'missing') === 'accepted'
  ).length;
  const providerRequired = actionable.filter(providerApprovalRequired);
  const providerAccepted = providerRequired.filter(
    (item) => providerApprovalSummary(item).label === 'Accepted'
  ).length;
  return [
    { key: 'packs', label: SOC_GATE_LABEL.packs, ...socPackGate(actionable.length, actionable.length - packAccepted) },
    {
      key: 'providers',
      label: SOC_GATE_LABEL.providers,
      tone: providerRequired.length === 0 ? 'muted' : providerAccepted === providerRequired.length ? 'success' : 'warn',
      status: providerRequired.length === 0
        ? 'Not required'
        : providerAccepted === providerRequired.length
          ? 'All accepted'
          : `${formatNumber(providerRequired.length - providerAccepted)} pending`
    },
    {
      key: 'kill',
      label: SOC_GATE_LABEL.kill,
      tone: context.killSwitchActive ? 'danger' : 'success',
      status: context.killSwitchActive ? 'Active' : 'Clear'
    },
    {
      key: 'execution',
      label: SOC_GATE_LABEL.execution,
      tone: context.runningCount > 0 ? 'info' : 'muted',
      status: context.runningCount > 0 ? `${formatNumber(context.runningCount)} running` : 'None running'
    },
    {
      key: 'findings',
      label: SOC_GATE_LABEL.findings,
      tone: context.openFindings > 0 ? 'info' : 'muted',
      status: context.openFindings > 0 ? `${formatNumber(context.openFindings)} open` : 'None open'
    }
  ];
}

function providerNameForRequest(item: DataItem): string {
  const context = getNestedItem(item, ['provider_context']);
  const contextName = getString(context, ['provider_name', 'provider', 'name'], '');
  if (contextName && contextName !== '—') return contextName;
  const checklist = Array.isArray(item.provider_approval_checklist)
    ? (item.provider_approval_checklist as DataItem[])
    : [];
  for (const entry of checklist) {
    const name = getString(entry, ['provider_name', 'provider', 'name'], '');
    if (name && name !== '—') return name;
  }
  return '';
}

function extractEmergencyContact(contact: unknown): { name: string; detail: string; role: string } {
  if (typeof contact === 'string') return { name: contact, detail: '', role: '' };
  if (contact && typeof contact === 'object' && !Array.isArray(contact)) {
    const item = contact as DataItem;
    return {
      name: getString(item, ['name', 'contact', 'email', 'phone'], '—'),
      detail: getString(item, ['contact', 'email', 'phone'], ''),
      role: getString(item, ['role', 'title'], '')
    };
  }
  return { name: '—', detail: '', role: '' };
}

type ProviderContactRow = { id: string; requestId: string; provider: string; contact: string; role: string };

function buildProviderContactRows(requests: DataItem[]): ProviderContactRow[] {
  return requests.flatMap((request) => {
    const requestId = getString(request, ['id'], '—');
    const provider = providerNameForRequest(request);
    const contacts = Array.isArray(request.emergency_contacts) ? request.emergency_contacts : [];
    if (contacts.length === 0) {
      if (!provider) return [];
      return [{ id: `${requestId}::provider`, requestId, provider, contact: '—', role: '—' }];
    }
    return contacts.map((contact, index) => {
      const info = extractEmergencyContact(contact);
      const label = info.detail && info.detail !== info.name ? `${info.name} · ${info.detail}` : info.name;
      return {
        id: `${requestId}::${index}`,
        requestId,
        provider: provider || '—',
        contact: label,
        role: info.role || '—'
      };
    });
  });
}

const providerContactColumns: TableColumn<ProviderContactRow>[] = [
  { key: 'request', label: 'Request', render: (item) => <span title={item.requestId}>High-scale request</span> },
  {
    key: 'provider',
    label: 'Provider',
    render: (item) => (item.provider === '—' ? <span className="muted">—</span> : <Badge tone="muted">{item.provider}</Badge>)
  },
  { key: 'contact', label: 'Contact', render: (item) => <span className="mono">{item.contact}</span> },
  {
    key: 'role',
    label: 'Role',
    render: (item) => (item.role === '—' ? <span className="muted">—</span> : formatGovernanceStatusLabel(item.role))
  }
];

type SocTimelineRow = { key: string; requestId: string; objective: string; action: string; at: string; by: string };

function buildSocExecutionTimeline(requests: DataItem[]): SocTimelineRow[] {
  return requests
    .flatMap((request) => {
      const requestId = getString(request, ['id'], '—');
      const objective = getString(request, ['objective', 'title', 'reason', 'name'], '');
      return buildLifecycleTimeline(request).map((event, index) => ({
        key: `${requestId}::${index}::${event.at}`,
        requestId,
        objective,
        action: event.action,
        at: event.at,
        by: event.by
      }));
    })
    .sort((left, right) => new Date(left.at).getTime() - new Date(right.at).getTime())
    .slice(-12);
}

type SocCrossTenantRow = {
  id: string;
  tenantId: string;
  tenantName: string;
  state: string;
  requestedAt: string;
  windowStart: string;
  windowEnd: string;
};

// Staff SOC surface only: rows come from GET /internal/admin/soc/high-scale-requests (staff:soc:read, audited).
function isHighScaleApprovalKind(kind: string) {
  return kind.trim().toLowerCase().startsWith('high_scale');
}

function isSocRunningState(state: string) {
  return SOC_RUNNING_STATES.includes(state.trim().toLowerCase());
}

function buildSocCrossTenantRows(approvals: DataItem[]): SocCrossTenantRow[] {
  return approvals
    .filter((item) => isHighScaleApprovalKind(getString(item, ['kind'], '')))
    .map((item) => ({
      id: getString(item, ['high_scale_request_id', 'subject_id', 'resource_id', 'request_id', 'id'], '—'),
      tenantId: getString(item, ['tenant_id'], '—'),
      tenantName: getString(item, ['tenant_name'], ''),
      state: getString(item, ['state'], '—'),
      requestedAt: getString(item, ['created_at', 'requested_at'], ''),
      windowStart: getNestedString(item, ['scheduled_window', 'window_start'], ''),
      windowEnd: getNestedString(item, ['scheduled_window', 'window_end'], '')
    }))
    .sort((left, right) => {
      const running = Number(isSocRunningState(right.state)) - Number(isSocRunningState(left.state));
      if (running !== 0) return running;
      return (Date.parse(right.requestedAt) || 0) - (Date.parse(left.requestedAt) || 0);
    });
}

function socWindowRange(start: string, end: string) {
  if (!start || !end) return '';
  return `${formatDate(start)} – ${formatDate(end)}`;
}

const SOC_WINDOW_BADGE: Record<string, { tone: GovernanceBadgeTone; label: string }> = {
  expired: { tone: 'danger', label: 'Expired' },
  open: { tone: 'success', label: 'Open' },
  upcoming: { tone: 'muted', label: 'Upcoming' },
  unscheduled: { tone: 'muted', label: 'Unscheduled' }
};

function SocWindowCell({ start, end, state, terminalWarn = false }: { start: string; end: string; state: string; terminalWarn?: boolean }) {
  const windowState = scheduledWindowState(start, end);
  const range = socWindowRange(start, end);
  if (terminalWarn) {
    const passed = windowState === 'expired' && !SOC_TERMINAL_STATES.includes(state.trim().toLowerCase());
    return (
      <span className="cp-stack">
        <span>{range || <span className="muted">Not scheduled</span>}</span>
        {passed ? <Badge tone="warn">Window passed</Badge> : null}
      </span>
    );
  }
  const badge = SOC_WINDOW_BADGE[windowState] ?? SOC_WINDOW_BADGE.unscheduled;
  return (
    <span className="cp-stack">
      <Badge tone={badge.tone}>{badge.label}</Badge>
      {range ? <span className="muted small">{range}</span> : null}
    </span>
  );
}

function socTenantLabel(name: string, id: string) {
  if (!id || id === '—') return name || 'Unknown tenant';
  return name ? `${name} (${id})` : id;
}

type AttemptView = {
  key: string;
  attempt: DataItem;
  event: DataItem;
  rule: DataItem | null;
  status: string;
};

const ATTEMPT_STATUS_COPY: Record<string, { label: string; tone: GovernanceBadgeTone; meaning: string }> = {
  delivered_provider: { label: 'Delivered', tone: 'success', meaning: 'The provider accepted the message.' },
  delivered_in_app: { label: 'In-app feed', tone: 'success', meaning: 'Recorded in the in-app feed.' },
  queued_provider_not_configured: { label: 'Recorded, not sent', tone: 'muted', meaning: 'Outbound delivery is not enabled on the server, so nothing was sent.' },
  provider_retry_scheduled: { label: 'Retry scheduled', tone: 'warn', meaning: 'A send failed and a retry is already scheduled.' },
  provider_failed_dlq: { label: 'Failed', tone: 'danger', meaning: 'Retries were exhausted. The attempt is parked until someone retries it.' }
};

function attemptStatusCopy(status: string) {
  return ATTEMPT_STATUS_COPY[status] ?? { label: status ? status.replaceAll('_', ' ') : 'Outcome not recorded', tone: 'warn' as GovernanceBadgeTone, meaning: 'The server recorded a status this page does not interpret. Treat the outcome as unknown.' };
}

function readNotificationParam(name: string) {
  const hash = window.location.hash.replace(/^#/, '');
  const index = hash.indexOf('?');
  return new URLSearchParams(index >= 0 ? hash.slice(index + 1) : '').get(name) ?? '';
}

export function NotificationsPage({
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
  const [busy, setBusy] = useState('');
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');
  const [channelError, setChannelError] = useState('');
  const [triggerError, setTriggerError] = useState('');
  const [ruleFormOpen, setRuleFormOpen] = useState(false);
  const [existingRuleId, setExistingRuleId] = useState('');
  const [ruleTriggers, setRuleTriggers] = useState<string[]>(() => [...DEFAULT_NOTIFICATION_TRIGGERS]);
  const [ruleEnabled, setRuleEnabled] = useState(true);
  const [selectedAttemptKey, setSelectedAttemptKey] = useState(() => readNotificationParam('focus'));
  const [attemptFilter, setAttemptFilter] = useState<'problems' | 'all'>('problems');
  const [retryPreview, setRetryPreview] = useState<{ key: string; summary: string } | null>(null);
  const [batchPreview, setBatchPreview] = useState<{ kind: 'retries' | 'failed'; summary: string } | null>(null);
  const formHeadingRef = useRef<HTMLHeadingElement>(null);
  const canWrite = canWriteNotifications(session.role);
  const rules = data.notificationRules ?? [];
  const events = useMemo(() => (data.notificationEvents ?? []).slice().sort((left, right) => String(right.created_at ?? '').localeCompare(String(left.created_at ?? ''))), [data.notificationEvents]);

  const attempts: AttemptView[] = useMemo(() => events.flatMap((event) => {
    const list = Array.isArray(event.delivery_attempts) ? event.delivery_attempts as DataItem[] : [];
    return list.map((attempt, index) => ({
      key: getString(attempt, ['id', 'attempt_id'], `${getString(event, ['id'], 'event')}-${index}`),
      attempt,
      event,
      rule: rules.find((rule) => getString(rule, ['id'], '') === getString(attempt, ['rule_id'], '')) ?? null,
      status: getString(attempt, ['status'], '')
    }));
  }), [events, rules]);
  const counts = useMemo(() => {
    const result = { delivered: 0, retry: 0, failed: 0, notSent: 0, unknown: 0 };
    for (const view of attempts) {
      if (view.status === 'delivered_provider' || view.status === 'delivered_in_app') result.delivered += 1;
      else if (view.status === 'provider_retry_scheduled') result.retry += 1;
      else if (view.status === 'provider_failed_dlq') result.failed += 1;
      else if (view.status === 'queued_provider_not_configured') result.notSent += 1;
      else result.unknown += 1;
    }
    return result;
  }, [attempts]);
  const problemAttempts = attempts.filter((view) => !['delivered_provider', 'delivered_in_app', 'queued_provider_not_configured'].includes(view.status));
  const visibleAttempts = attemptFilter === 'problems' ? problemAttempts : attempts;
  const selected = attempts.find((view) => view.key === selectedAttemptKey) ?? null;
  const enabledRules = rules.filter((rule) => rule.enabled !== false).length;
  const eventsUnavailable = Boolean(data.loadErrors.notificationEvents);

  useEffect(() => {
    replaceRouteParams({ focus: selectedAttemptKey || null });
    setRetryPreview(null);
  }, [selectedAttemptKey]);

  useEffect(() => {
    if (ruleFormOpen) formHeadingRef.current?.focus();
  }, [ruleFormOpen]);

  async function runAction<T>(label: string, action: () => Promise<T>, success: string) {
    setBusy(label);
    setError('');
    setMessage('');
    try {
      const result = await action();
      setMessage(success);
      await onRefresh();
      return result;
    } catch (err) {
      setError(apiErrorMessage(err, 'Notification action failed.'));
      return null;
    } finally {
      setBusy('');
    }
  }

  function toggleRuleTrigger(trigger: string) {
    setTriggerError('');
    setRuleTriggers((current) => current.includes(trigger) ? current.filter((item) => item !== trigger) : [...current, trigger]);
  }

  async function handleAddEvents(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const triggers = NOTIFICATION_TRIGGER_OPTIONS.map((option) => option.id).filter((trigger) => ruleTriggers.includes(trigger));
    const rule = rules.find((item) => getString(item, ['id'], '') === existingRuleId);
    setChannelError(rule ? '' : 'Choose a channel.');
    setTriggerError(triggers.length ? '' : 'Choose at least one event to route.');
    if (!rule || triggers.length === 0) return;
    const merged = [...new Set([...(Array.isArray(rule.triggers) ? (rule.triggers as unknown[]).map(String) : []), ...triggers])];
    const updated = await runAction('add-notification-events', () => requestJson(config, session, `/v1/notifications/${encodeURIComponent(existingRuleId)}`, {
      method: 'PATCH',
      body: { triggers: merged, enabled: ruleEnabled }
    }), `Routed ${triggers.map(notificationTriggerLabel).join(', ')} to the ${notificationChannelLabel(getString(rule, ['channel'], ''))} channel ${getString(rule, ['destination_preview'], '')}. Its stored destination was not changed.`);
    if (updated) setRuleFormOpen(false);
  }

  async function previewAttemptRetry(view: AttemptView) {
    const id = getString(view.attempt, ['id', 'attempt_id'], '');
    if (!id) return;
    const result = await runAction(`preview-${view.key}`, () => requestJson(config, session, '/v1/notifications/dlq/redrive', {
      method: 'POST',
      body: { dry_run: true, attempt_ids: [id] }
    }), 'Retry preview ready. Nothing was sent or changed.') as DataItem | null;
    if (result) setRetryPreview({ key: view.key, summary: summarizeOperationResult(result) });
  }

  async function retryAttempt(view: AttemptView) {
    const id = getString(view.attempt, ['id', 'attempt_id'], '');
    if (!id) return;
    const destination = getString(view.attempt, ['destination_preview'], getString(view.rule ?? {}, ['destination_preview'], 'its destination'));
    if (!await confirm({
      title: 'Retry this delivery',
      description: `Requeue the failed ${getString(view.attempt, ['channel'], 'notification')} delivery for "${getString(view.event, ['subject'], 'this event')}" to ${destination}? The portal records the retry in metadata-only mode; whether a message is sent depends on your deployment's delivery configuration. If the provider did receive the original, the recipient may see a duplicate.`,
      confirmLabel: 'Retry delivery',
      confirmTone: 'default'
    })) return;
    await runAction(`retry-${view.key}`, () => requestJson(config, session, '/v1/notifications/dlq/redrive', {
      method: 'POST',
      body: { dry_run: false, attempt_ids: [id] }
    }), 'Delivery requeued for retry.');
    setRetryPreview(null);
  }

  async function previewBatch(kind: 'retries' | 'failed') {
    const result = await runAction(`batch-preview-${kind}`, () => requestJson(config, session, kind === 'retries' ? '/v1/notifications/retries/process' : '/v1/notifications/dlq/redrive', {
      method: 'POST',
      body: kind === 'retries'
        ? { dry_run: true }
        : { dry_run: true, attempt_ids: attempts.filter((view) => view.status === 'provider_failed_dlq').map((view) => getString(view.attempt, ['id', 'attempt_id'], '')).filter(Boolean) }
    }), 'Preview ready. Nothing was sent or changed.') as DataItem | null;
    if (result) setBatchPreview({ kind, summary: summarizeOperationResult(result) });
  }

  async function runBatch(kind: 'retries' | 'failed') {
    const failedIds = attempts.filter((view) => view.status === 'provider_failed_dlq').map((view) => getString(view.attempt, ['id', 'attempt_id'], '')).filter(Boolean);
    if (!await confirm({
      title: kind === 'retries' ? 'Process due retries' : 'Retry all failed deliveries',
      description: kind === 'retries'
        ? `Process retries that are due now (${batchPreview?.summary ?? 'see preview'})? Recorded in metadata-only mode from the portal. Recipients may see duplicates if earlier sends actually arrived.`
        : `Requeue ${formatNumber(failedIds.length)} failed deliveries listed on this page? Recorded in metadata-only mode from the portal. Recipients may see duplicates if earlier sends actually arrived.`,
      confirmLabel: kind === 'retries' ? 'Process retries' : 'Retry failed deliveries',
      confirmTone: 'default'
    })) return;
    await runAction(`batch-${kind}`, () => requestJson(config, session, kind === 'retries' ? '/v1/notifications/retries/process' : '/v1/notifications/dlq/redrive', {
      method: 'POST',
      body: kind === 'retries' ? { dry_run: false } : { dry_run: false, attempt_ids: failedIds }
    }), kind === 'retries' ? 'Due retries processed.' : 'Failed deliveries requeued.');
    setBatchPreview(null);
  }

  const ruleColumns: TableColumn<DataItem>[] = [
    {
      key: 'channel',
      label: 'Channel',
      render: (item) => {
        const channel = getString(item, ['channel']);
        return (
          <span className="cp-stack">
            <span>{notificationChannelLabel(channel)}</span>
            <span className="muted small mono">{getString(item, ['destination_preview'], 'Destination hidden')}</span>
          </span>
        );
      }
    },
    { key: 'triggers', label: 'Routes', render: (item) => (Array.isArray(item.triggers) ? (item.triggers as unknown[]).map((trigger) => notificationTriggerLabel(String(trigger))).join(', ') : '') || <span className="muted">No events</span> },
    { key: 'enabled', label: 'Sending', render: (item) => <Badge tone="muted">{item.enabled === false ? 'Disabled' : 'Enabled'}</Badge> },
    {
      key: 'last',
      label: 'Last attempt',
      render: (item) => {
        const last = attempts.find((view) => getString(view.attempt, ['rule_id'], '') === getString(item, ['id'], ''));
        if (!last) return <span className="muted">None in loaded events</span>;
        const copy = attemptStatusCopy(last.status);
        return <span className="cp-stack"><Badge tone={copy.tone}>{copy.label}</Badge><span className="muted small">{formatDate(last.attempt.attempted_at ?? last.attempt.created_at ?? last.event.created_at)}</span></span>;
      }
    },
    { key: 'edit', label: 'Configuration', render: (item) => <AnchorButton size="sm" variant="ghost" href={`#integrations?focus=${encodeURIComponent(getString(item, ['id'], ''))}`}>Open channel</AnchorButton> }
  ];

  const attemptColumns: TableColumn<AttemptView>[] = [
    { key: 'status', label: 'Outcome', render: (view) => { const copy = attemptStatusCopy(view.status); return <Badge tone={copy.tone}>{copy.label}</Badge>; } },
    { key: 'time', label: 'Attempted', render: (view) => <span className="mono">{formatDate(view.attempt.attempted_at ?? view.attempt.created_at ?? view.event.created_at)}</span> },
    { key: 'event', label: 'Event', render: (view) => <span className="cp-stack"><span>{notificationTriggerLabel(getString(view.event, ['trigger']))}</span><span className="muted small">{getString(view.event, ['subject'], '')}</span></span> },
    { key: 'channel', label: 'Channel', render: (view) => <span className="cp-stack"><span>{formatGovernanceStatusLabel(getString(view.attempt, ['channel'], ''), 'Not recorded')}</span><span className="muted small mono">{getString(view.attempt, ['destination_preview'], getString(view.rule ?? {}, ['destination_preview'], ''))}</span></span> },
  ];

  const selectedCopy = selected ? attemptStatusCopy(selected.status) : null;
  const selectedAttemptNumber = selected ? getString(selected.attempt, ['attempt_number'], '') : '';
  const selectedMaxAttempts = selected ? getString(selected.attempt, ['max_attempts'], '') : '';

  return (
    <div className="content notifications-page">
      <CustomerPageStyles />
      <PageHeader
        route="notifications"
        title="Notifications"
        description={<>Each channel receives the events chosen for it. Channels are set up in <a className="cp-link" href="#integrations">Integrations</a>. An event being recorded is not a message delivered.</>}
        actions={!canWrite ? <Badge tone="muted">Read only</Badge> : rules.length === 0 ? (
          <AnchorButton size="sm" href="#integrations">Set up a channel in Integrations</AnchorButton>
        ) : (
          <Button
            size="sm"
            variant={ruleFormOpen ? 'ghost' : 'default'}
            aria-expanded={ruleFormOpen}
            aria-controls={ruleFormOpen ? 'notifications-create-rule' : undefined}
            onClick={() => setRuleFormOpen((open) => !open)}
          >
            {ruleFormOpen ? 'Close events form' : 'Choose events'}
          </Button>
        )}
      />
      <div className="kpi-row" role="group" aria-label="Delivery summary for loaded events">
        <KpiCell label="Channels" value={`${formatNumber(enabledRules)} of ${formatNumber(rules.length)}`} delta="enabled" />
        <KpiCell label="Delivered" value={eventsUnavailable ? '—' : formatNumber(counts.delivered)} delta="attempts accepted by a provider or in-app" />
        <KpiCell label="Failed or retrying" value={eventsUnavailable ? '—' : formatNumber(counts.failed + counts.retry)} delta={`${formatNumber(counts.failed)} failed · ${formatNumber(counts.retry)} retry scheduled`} />
        <KpiCell label="Recorded, not sent" value={eventsUnavailable ? '—' : formatNumber(counts.notSent)} delta={`outbound delivery disabled${counts.unknown ? ` · ${formatNumber(counts.unknown)} unknown` : ''}`} />
      </div>
      {events.length > 0 ? (
        <p className="muted small">Counts cover the {formatNumber(events.length)} most recent {pluralize(events.length, 'event')} loaded, not all history.</p>
      ) : null}
      <GovernanceFeedbackBanner message={message} error={error} />

      {canWrite && ruleFormOpen && rules.length > 0 ? (
        <Card id="notifications-create-rule" raised>
          <CardHeader>
            <div>
              <CardTitle><span ref={formHeadingRef} tabIndex={-1}>Choose events for a channel</span></CardTitle>
              <CardDescription>Add events to a channel you already set up in Integrations. Its destination is not changed, and saving sends nothing.</CardDescription>
            </div>
          </CardHeader>
          <CardContent>
            <form className="product-form" onSubmit={handleAddEvents} aria-busy={busy === 'add-notification-events'} noValidate>
              <Select
                className="full"
                label="Channel"
                value={existingRuleId}
                options={[{ value: '', label: 'Choose a channel' }, ...rules.map((rule) => ({
                  value: getString(rule, ['id'], ''),
                  label: `${notificationChannelLabel(getString(rule, ['channel'], ''))} · ${getString(rule, ['destination_preview'], 'destination hidden')}`
                }))]}
                onChange={(value) => { setExistingRuleId(value); setChannelError(''); }}
                error={channelError || undefined}
              />
              <fieldset className="full">
                <legend>Events to route</legend>
                {NOTIFICATION_TRIGGER_OPTIONS.map((option) => (
                  <label key={option.id} className="check-row">
                    <input type="checkbox" name="triggers" value={option.id} checked={ruleTriggers.includes(option.id)} onChange={() => toggleRuleTrigger(option.id)} disabled={busy !== ''} />
                    <span className="cp-stack">
                      <span>{option.label}</span>
                      <span className="muted small">{option.detail}</span>
                    </span>
                  </label>
                ))}
              </fieldset>
              {triggerError ? <p className="field-error full" role="alert">{triggerError}</p> : null}
              <label className="check-row full">
                <input type="checkbox" name="enabled" checked={ruleEnabled} onChange={(changeEvent) => setRuleEnabled(changeEvent.target.checked)} disabled={busy !== ''} />
                <span>Channel enabled after saving</span>
              </label>
              <div className="form-actions full">
                <Button type="button" variant="ghost" disabled={busy !== ''} onClick={() => setRuleFormOpen(false)}>Cancel</Button>
                <Button type="submit" loading={busy === 'add-notification-events'} disabled={busy !== '' && busy !== 'add-notification-events'}>Add events</Button>
              </div>
            </form>
          </CardContent>
        </Card>
      ) : null}

      <div className={selected ? 'release-ledger has-selection' : 'release-ledger'}>
        <Card>
          <PanelCardHeader
            title="Delivery attempts"
            description="Select an attempt to see its event, channel, and configuration."
            trailing={(
              <div className="cp-toolbar" role="group" aria-label="Filter attempts">
                <button type="button" className={`filter-chip${attemptFilter === 'problems' ? ' is-active' : ''}`} aria-pressed={attemptFilter === 'problems'} onClick={() => setAttemptFilter('problems')}>Needs attention {formatNumber(problemAttempts.length)}</button>
                <button type="button" className={`filter-chip${attemptFilter === 'all' ? ' is-active' : ''}`} aria-pressed={attemptFilter === 'all'} onClick={() => setAttemptFilter('all')}>All {formatNumber(attempts.length)}</button>
              </div>
            )}
          />
          <CardContent>
            <DataTable
              columns={attemptColumns}
              items={visibleAttempts}
              getRowId={(view) => view.key}
              selectedId={selectedAttemptKey || null}
              getRowProps={(view) => ({
                tabIndex: 0,
                'aria-label': `Inspect ${attemptStatusCopy(view.status).label.toLowerCase()} delivery for ${notificationTriggerLabel(getString(view.event, ['trigger']))}`,
                onClick: () => setSelectedAttemptKey(view.key),
                onKeyDown: (event) => {
                  if (event.key !== 'Enter' && event.key !== ' ') return;
                  event.preventDefault();
                  setSelectedAttemptKey(view.key);
                }
              })}
              loadError={data.loadErrors.notificationEvents}
              onRetry={() => void onRefresh()}
              empty={attempts.length > 0
                ? <EmptyState icon={CheckCircle2} title="No failed or retrying deliveries." body="Every loaded attempt was delivered or recorded without sending." actionLabel="Show all attempts" onAction={() => setAttemptFilter('all')} />
                : rules.length
                  ? <EmptyState icon={ClipboardList} title="No delivery attempts recorded." body="Attempts appear when a routed event occurs." />
                  : <EmptyState icon={ClipboardList} title="No delivery attempts recorded." body="Set up a channel first; attempts appear when a routed event occurs." actionLabel="Set up a channel in Integrations" actionHref="#integrations" />}
            />
          </CardContent>
        </Card>
        {selected && selectedCopy ? (
          <Card className="release-record-detail" raised>
            <section aria-label="Selected delivery attempt">
              <CardHeader>
                <div>
                  <CardTitle>{selectedCopy.label}: {notificationTriggerLabel(getString(selected.event, ['trigger']))}</CardTitle>
                  <CardDescription>{selectedCopy.meaning}</CardDescription>
                </div>
                <Button size="sm" variant="ghost" onClick={() => setSelectedAttemptKey('')}>Close</Button>
              </CardHeader>
              <CardContent className="stack-tight">
                <div className="kv-list">
                  <KvField label="Attempted">{formatDate(selected.attempt.attempted_at ?? selected.attempt.created_at)}</KvField>
                  <KvField label="Reason">{getString(selected.attempt, ['reason', 'provider_error'], 'Not recorded')}</KvField>
                  <KvField label="Attempt">{selectedAttemptNumber ? `${selectedAttemptNumber}${selectedMaxAttempts ? ` of ${selectedMaxAttempts}` : ''}` : 'Not recorded'}</KvField>
                  <KvField label="Event">{getString(selected.event, ['subject'], 'Not recorded')} · {formatDate(selected.event.created_at)}</KvField>
                  <KvField label="Channel">{formatGovernanceStatusLabel(getString(selected.attempt, ['channel'], ''), 'Not recorded')} <span className="mono muted">{getString(selected.attempt, ['destination_preview'], '')}</span></KvField>
                  <KvField label="Channel routing">{selected.rule ? `${selected.rule.enabled === false ? 'Disabled' : 'Enabled'} · routes ${(Array.isArray(selected.rule.triggers) ? (selected.rule.triggers as unknown[]).length : 0)} event types` : 'Channel removed or not recorded'}</KvField>
                </div>
                <div className="row-actions">
                  {selected.rule ? <AnchorButton size="sm" variant="secondary" href={`#integrations?focus=${encodeURIComponent(getString(selected.rule, ['id'], ''))}`}>Fix channel configuration</AnchorButton> : null}
                </div>
                {selected.status === 'provider_failed_dlq' ? (
                  canWrite ? (
                    <div className="stack-tight">
                      <p className="muted small">Fix the channel first if the reason points to a bad destination. Preview the retry, then retry explicitly.</p>
                      <div className="row-actions">
                        <Button size="sm" variant="secondary" loading={busy === `preview-${selected.key}`} disabled={busy !== ''} onClick={() => void previewAttemptRetry(selected)}>Preview retry</Button>
                        <Button size="sm" loading={busy === `retry-${selected.key}`} disabled={busy !== '' || retryPreview?.key !== selected.key} onClick={() => void retryAttempt(selected)}>Retry delivery</Button>
                      </div>
                      {retryPreview?.key === selected.key ? <p className="muted small" role="status">Preview: {retryPreview.summary}</p> : null}
                    </div>
                  ) : <p className="muted small">Owner or admin role is required to retry deliveries.</p>
                ) : selected.status === 'provider_retry_scheduled' ? (
                  <p className="muted small">A retry is already scheduled. No manual retry is offered, to avoid sending twice.</p>
                ) : !ATTEMPT_STATUS_COPY[selected.status] ? (
                  <p className="form-banner neutral">The outcome is unknown, so retry is not offered. Retrying an attempt that may have been delivered risks a duplicate; check the destination first.</p>
                ) : null}
              </CardContent>
            </section>
          </Card>
        ) : selectedAttemptKey && attempts.length > 0 ? (
          <div className="form-banner neutral" role="status">
            Attempt {selectedAttemptKey} is not among the loaded events. <button type="button" className="rf-link-button" onClick={() => setSelectedAttemptKey('')}>Clear selection</button>
          </div>
        ) : null}
      </div>

      <Card>
        <PanelCardHeader title="Channels" description="Each channel receives the events chosen for it. Set up, turn on or off, and remove channels in Integrations." />
        <CardContent>
          <DataTable
            columns={ruleColumns}
            items={rules}
            getRowId={(item) => getString(item, ['id'], '')}
            empty={<EmptyState icon={Bell} title="No channels yet." body="Nothing is routed to a channel yet." actionLabel={canWrite ? 'Set up a channel in Integrations' : undefined} actionHref={canWrite ? '#integrations' : undefined} />}
            loadError={data.loadErrors.notificationRules}
            onRetry={() => void onRefresh()}
          />
        </CardContent>
      </Card>

      {canWrite && (events.length > 0 || eventsUnavailable) ? (
        <Card>
          <PanelCardHeader title="Bulk recovery" description="Preview first. Live actions apply to every matching attempt and can produce duplicates if earlier sends arrived." />
          <CardContent className="stack-tight">
            <DeliveryOperationPanel
              titleId="notification-retries-title"
              title="Due retries"
              description={batchPreview?.kind === 'retries' ? `Preview: ${batchPreview.summary}` : 'Process retries whose scheduled time has passed.'}
              note={batchPreview?.kind !== 'retries' ? 'Preview due retries first.' : undefined}
              noteId="notification-retries-reason"
            >
              <Button size="sm" variant="secondary" loading={busy === 'batch-preview-retries'} disabled={busy !== ''} onClick={() => void previewBatch('retries')}>Preview due retries</Button>
              <Button
                size="sm"
                variant="secondary"
                loading={busy === 'batch-retries'}
                disabled={busy !== '' || batchPreview?.kind !== 'retries'}
                aria-describedby={batchPreview?.kind !== 'retries' ? 'notification-retries-reason' : undefined}
                onClick={() => void runBatch('retries')}
              >Process due retries</Button>
            </DeliveryOperationPanel>
            <DeliveryOperationPanel
              titleId="notification-failed-title"
              title="Failed deliveries"
              description={batchPreview?.kind === 'failed' ? `Preview: ${batchPreview.summary}` : `${formatNumber(counts.failed)} failed attempt${counts.failed === 1 ? '' : 's'} on this page.`}
              note={counts.failed > 0 && batchPreview?.kind !== 'failed' ? 'Preview retry of failed first.' : undefined}
              noteId="notification-failed-reason"
            >
              <Button size="sm" variant="secondary" loading={busy === 'batch-preview-failed'} disabled={busy !== '' || counts.failed === 0} onClick={() => void previewBatch('failed')}>Preview retry of failed</Button>
              <Button
                size="sm"
                variant="secondary"
                loading={busy === 'batch-failed'}
                disabled={busy !== '' || counts.failed === 0 || batchPreview?.kind !== 'failed'}
                aria-describedby={counts.failed > 0 && batchPreview?.kind !== 'failed' ? 'notification-failed-reason' : undefined}
                onClick={() => void runBatch('failed')}
              >Retry failed deliveries</Button>
            </DeliveryOperationPanel>
          </CardContent>
        </Card>
      ) : null}
    </div>
  );
}

function summarizeOperationResult(result: DataItem) {
  const parts: string[] = [];
  const labels: Array<[string, string]> = [
    ['due_count', 'due'],
    ['requeued_count', 'would be requeued'],
    ['still_dlq_count', 'still failed'],
    ['skipped_count', 'skipped'],
    ['held_count', 'held'],
    ['cancelled_count', 'cancelled'],
    ['scheduled_not_due_count', 'scheduled, not yet due'],
    ['network_sends_performed', 'messages sent']
  ];
  for (const [key, label] of labels) {
    const value = result[key];
    if (typeof value === 'number') parts.push(`${value} ${label}`);
  }
  if (typeof result.delivery_mode === 'string') parts.push(`mode ${result.delivery_mode.replaceAll('_', ' ')}`);
  return parts.length ? parts.join(' · ') : 'the server returned no counts';
}

const AUDIT_PAGE_SIZE = 50;
const AUDIT_RESOURCE_ROUTES: Record<string, string> = {
  target: 'target-detail',
  finding: 'finding-detail',
  report: 'report-detail',
  test_policy: 'policy-detail',
  evidence: 'evidence-detail'
};

function auditTimestamp(entry: DataItem) {
  return String(entry.timestamp ?? entry.created_at ?? '');
}

function auditActionCategory(action: string) {
  const index = action.indexOf('.');
  return index > 0 ? action.slice(0, index) : action;
}

function auditDayBound(value: string, end: boolean) {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(value)) return NaN;
  const [year, month, day] = value.split('-').map(Number);
  const at = end ? new Date(year, month - 1, day, 23, 59, 59, 999) : new Date(year, month - 1, day, 0, 0, 0, 0);
  return at.getTime();
}

function readAuditParam(name: string) {
  const hash = window.location.hash.replace(/^#/, '');
  const index = hash.indexOf('?');
  return new URLSearchParams(index >= 0 ? hash.slice(index + 1) : '').get(name) ?? '';
}

function incomingAuditEventId() {
  const ref = parseInspectorRef(window.location.hash);
  if (ref?.entry === 'audit' && ref.audit_id) return ref.audit_id;
  return readAuditParam('event');
}

type AuditFilters = { actor: string; action: string; resource: string; since: string; until: string };

const EMPTY_AUDIT_FILTERS: AuditFilters = { actor: '', action: '', resource: '', since: '', until: '' };

function readAuditFilters(): AuditFilters {
  return {
    actor: readAuditParam('actor'),
    action: readAuditParam('category'),
    resource: readAuditParam('resource'),
    since: /^\d{4}-\d{2}-\d{2}$/.test(readAuditParam('from')) ? readAuditParam('from') : '',
    until: /^\d{4}-\d{2}-\d{2}$/.test(readAuditParam('to')) ? readAuditParam('to') : ''
  };
}

function auditFilterParams(filters: AuditFilters) {
  const params = new URLSearchParams();
  if (filters.actor.trim()) params.set('actor', filters.actor.trim());
  if (filters.action.trim()) params.set('action', filters.action.trim());
  if (filters.resource.trim()) params.set('resource', filters.resource.trim());
  const since = auditDayBound(filters.since, false);
  const until = auditDayBound(filters.until, true);
  if (Number.isFinite(since)) params.set('since', new Date(since).toISOString());
  if (Number.isFinite(until)) params.set('until', new Date(until).toISOString());
  return params;
}

/** Server query for the exact filters the user applied; local calendar days become inclusive instants. */
export function auditListQuery(filters: AuditFilters, cursor: string, limit = AUDIT_PAGE_SIZE) {
  const params = auditFilterParams(filters);
  if (cursor) params.set('cursor', cursor);
  params.set('limit', String(limit));
  return `/v1/audit-log?${params.toString()}`;
}

/** Export of every entry matching the applied filters; the server pages internally. */
export function auditExportQuery(filters: AuditFilters) {
  const query = auditFilterParams(filters).toString();
  return `/v1/audit-log/export${query ? `?${query}` : ''}`;
}

export function auditExportFilename(filters: AuditFilters, digest: string) {
  const digest8 = digest.replace(/^sha256:/, '').slice(0, 8) || 'nodigest';
  return `audit-log-${filters.since || 'start'}-${filters.until || 'now'}-${digest8}.json`;
}

/** Map a typed label (as shown in the table) back to its stored key; keys and dotted values pass through. */
export function resolveAuditFilterKey(typed: string, labels: ReadonlyMap<string, string>) {
  const value = typed.trim();
  if (!value || value.includes('.')) return value;
  return labels.get(value.toLowerCase()) ?? value;
}

export function AuditPage({
  data,
  session,
  config,
  onRefresh
}: {
  data: PortalData;
  session: Session;
  config?: PortalConfig;
  onRefresh?: () => void | Promise<void>;
}) {
  const allowed = canReadAudit(session.role);
  const [draft, setDraft] = useState<AuditFilters>(readAuditFilters);
  const [applied, setApplied] = useState<AuditFilters>(readAuditFilters);
  const [cursorStack, setCursorStack] = useState<string[]>(['']);
  const [reloadTick, setReloadTick] = useState(0);
  const [listState, setListState] = useState<{ status: 'loading' | 'ready' | 'error' | 'denied'; items: DataItem[]; total: number | null; nextCursor: string; error: string }>({ status: 'loading', items: [], total: null, nextCursor: '', error: '' });
  const [selectedId, setSelectedId] = useState(incomingAuditEventId);
  const [exact, setExact] = useState<{ id: string; status: 'idle' | 'loading' | 'found' | 'not_found' | 'denied' | 'error'; entry: DataItem | null }>({ id: '', status: 'idle', entry: null });
  const [exactTick, setExactTick] = useState(0);
  const [showRawAuditMetadata, setShowRawAuditMetadata] = useState(false);
  const [copyNotice, setCopyNotice] = useState('');
  const [dateError, setDateError] = useState('');
  const [exportState, setExportState] = useState<{ status: 'idle' | 'loading' | 'done' | 'error'; message: string }>({ status: 'idle', message: '' });
  const configRef = useRef<PortalConfig | null>(config ?? null);
  const viewerZone = (() => {
    try { return Intl.DateTimeFormat().resolvedOptions().timeZone || 'local time'; } catch { return 'local time'; }
  })();
  const currentCursor = cursorStack[cursorStack.length - 1] ?? '';

  async function resolvedConfig() {
    if (config) return config;
    if (!configRef.current) configRef.current = await fetchPortalConfig();
    return configRef.current;
  }

  useEffect(() => {
    function onHashChange() {
      const next = incomingAuditEventId();
      if (next) setSelectedId(next);
    }
    window.addEventListener('hashchange', onHashChange);
    return () => window.removeEventListener('hashchange', onHashChange);
  }, []);

  useEffect(() => {
    replaceRouteParams({
      actor: applied.actor || null,
      category: applied.action || null,
      resource: applied.resource || null,
      from: applied.since || null,
      to: applied.until || null,
      event: selectedId && !parseInspectorRef(window.location.hash) ? selectedId : null
    });
  }, [applied, selectedId]);

  useEffect(() => {
    if (!allowed) return undefined;
    let cancelled = false;
    setListState((current) => ({ ...current, status: 'loading', error: '' }));
    (async () => {
      try {
        const payload = await requestJson(await resolvedConfig(), session, auditListQuery(applied, currentCursor)) as DataItem;
        if (cancelled) return;
        const items = Array.isArray(payload?.items) ? (payload.items as DataItem[]) : [];
        const total = typeof payload?.total === 'number' ? payload.total : null;
        setListState({ status: 'ready', items, total, nextCursor: getString(payload, ['next_cursor'], ''), error: '' });
      } catch (err) {
        if (cancelled) return;
        const status = Number((err as { status?: unknown })?.status ?? 0);
        setListState({ status: status === 403 ? 'denied' : 'error', items: [], total: null, nextCursor: '', error: apiErrorMessage(err, 'The audit log could not be loaded.') });
      }
    })();
    return () => { cancelled = true; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [allowed, applied, currentCursor, reloadTick]);

  const items = [...listState.items].sort((left, right) => {
    const leftAt = Date.parse(auditTimestamp(left));
    const rightAt = Date.parse(auditTimestamp(right));
    return (Number.isFinite(rightAt) ? rightAt : 0) - (Number.isFinite(leftAt) ? leftAt : 0);
  });
  const onPage = selectedId ? items.find((entry) => auditEntrySelectionKey(entry) === selectedId) ?? null : null;

  useEffect(() => {
    if (!allowed || !selectedId || onPage || listState.status === 'loading') return undefined;
    if (exact.id === selectedId && exact.status !== 'idle' && exactTick === 0) return undefined;
    let cancelled = false;
    setExact({ id: selectedId, status: 'loading', entry: null });
    (async () => {
      try {
        const payload = await requestJson(await resolvedConfig(), session, `/v1/audit-log/${encodeURIComponent(selectedId)}`) as DataItem;
        if (cancelled) return;
        const entry = getNestedItem(payload, ['entry']);
        setExact(entry && getString(entry, ['id'], '') === selectedId ? { id: selectedId, status: 'found', entry } : { id: selectedId, status: 'not_found', entry: null });
      } catch (err) {
        if (cancelled) return;
        const status = Number((err as { status?: unknown })?.status ?? 0);
        setExact({ id: selectedId, status: status === 404 ? 'not_found' : status === 403 ? 'denied' : 'error', entry: null });
      }
    })();
    return () => { cancelled = true; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [allowed, selectedId, Boolean(onPage), listState.status, exactTick]);

  const selectedEntry = onPage ?? (exact.id === selectedId && exact.status === 'found' ? exact.entry : null);
  const selectedOffPage = Boolean(selectedEntry) && !onPage;

  useEffect(() => {
    setShowRawAuditMetadata(false);
    setCopyNotice('');
  }, [selectedId]);

  const actionLabelKeys = useMemo(() => {
    const map = new Map<string, string>();
    for (const [key, label] of Object.entries(AUDIT_ACTION_LABELS)) map.set(label.toLowerCase(), key);
    for (const entry of listState.items) {
      const key = getString(entry, ['action'], '');
      if (!key || key === '—') continue;
      map.set(formatAuditAction(key).toLowerCase(), key);
      map.set(formatAuditAction(key, key, entry.metadata).toLowerCase(), key);
    }
    return map;
  }, [listState.items]);
  const resourceLabelKeys = useMemo(() => {
    const map = new Map<string, string>();
    for (const [key, label] of Object.entries(RESOURCE_TYPE_LABELS)) map.set(label.toLowerCase(), key);
    for (const entry of listState.items) {
      const key = getString(entry, ['resource_type'], '');
      if (key && key !== '—') map.set(formatResourceTypeLabel(key).toLowerCase(), key);
    }
    return map;
  }, [listState.items]);

  function applyFilterValues(next: AuditFilters) {
    if (next.since && next.until && next.since > next.until) {
      setDateError('The start date is after the end date. Fix the range before applying.');
      return;
    }
    setDateError('');
    const resolved = {
      ...next,
      actor: next.actor.trim(),
      action: resolveAuditFilterKey(next.action, actionLabelKeys),
      resource: resolveAuditFilterKey(next.resource, resourceLabelKeys)
    };
    setDraft(resolved);
    setApplied(resolved);
    setCursorStack(['']);
    setExportState({ status: 'idle', message: '' });
  }

  function applyFilters(event?: FormEvent<HTMLFormElement>) {
    event?.preventDefault();
    applyFilterValues(draft);
  }

  function filterTo(field: 'actor' | 'action' | 'resource', value: string) {
    if (!value || value === '—') return;
    applyFilterValues({ ...draft, [field]: value });
  }

  async function exportFilteredEvents() {
    setExportState({ status: 'loading', message: '' });
    try {
      const payload = await requestJson(await resolvedConfig(), session, auditExportQuery(applied)) as DataItem;
      const digest = getNestedString(payload, ['custody', 'content_sha256'], '');
      const count = typeof payload?.count === 'number' ? payload.count : 0;
      downloadJsonFile(auditExportFilename(applied, digest), payload);
      setExportState({ status: 'done', message: `Exported ${formatNumber(count)} ${pluralize(count, 'event')} with their hashes. The export itself was recorded in the audit log.` });
    } catch (err) {
      setExportState({ status: 'error', message: apiErrorMessage(err, 'The audit export could not be created.') });
    }
  }

  function clearFilters() {
    setDraft(EMPTY_AUDIT_FILTERS);
    setApplied(EMPTY_AUDIT_FILTERS);
    setCursorStack(['']);
    setDateError('');
    setExportState({ status: 'idle', message: '' });
  }

  const filtersActive = Object.values(applied).some(Boolean);
  const suggestions = (key: 'actor_user_id' | 'action' | 'resource_type') => [...new Set(items.map((entry) => getString(entry, [key], '')).filter((value) => value && value !== '—'))].sort();
  const actorOptions = [...new Map(items.flatMap((entry) => {
    const id = getString(entry, ['actor_user_id'], '');
    if (!id || id === '—') return [];
    const role = getString(entry, ['actor_role'], '');
    return [[id, role && role !== '—' ? plainCodeLabel(role) : 'Role not recorded'] as const];
  })).entries()].sort(([left], [right]) => left.localeCompare(right));
  const actionOptions = [...new Set([...AUDIT_ACTIONS.map((entry) => entry.value), ...suggestions('action')])].sort();
  const resourceOptions = [...new Set([...Object.keys(RESOURCE_TYPE_LABELS), ...suggestions('resource_type')])].sort();
  const nothingToExport = listState.status === 'ready' && (listState.total === 0 || (listState.total === null && items.length === 0 && cursorStack.length === 1));
  const exportDisabledReason = listState.status === 'loading'
    ? 'Wait for the events to load.'
    : listState.status !== 'ready'
      ? 'Events could not be loaded, so there is nothing to export.'
      : nothingToExport
        ? 'No events match the applied filters, so there is nothing to export.'
        : '';

  function formatAuditHash(item: DataItem) {
    const hash = getString(item, ['entry_hash'], '');
    if (!hash || hash === '—') return '';
    return hash.length <= 12 ? hash : `${hash.slice(0, 6)}…${hash.slice(-4)}`;
  }

  function resourceCell(item: DataItem) {
    const resourceType = getString(item, ['resource_type'], '');
    const resourceId = getString(item, ['resource_id'], '');
    const sensitiveLabel = sensitiveResourceLabel(resourceType);
    if (sensitiveLabel) return <span title={resourceId !== '—' ? resourceId : undefined}>{sensitiveLabel}</span>;
    return (
      <span className="cp-stack">
        <span>{formatResourceTypeLabel(resourceType || 'resource')}</span>
        {resourceId && resourceId !== '—' ? <span className="mono muted small">{resourceId}</span> : null}
      </span>
    );
  }

  const columns: TableColumn<DataItem>[] = [
    { key: 'time', label: `Time (${viewerZone})`, render: (item) => <span className="mono">{auditTimestamp(item) ? formatDate(auditTimestamp(item)) : 'Not recorded'}</span> },
    {
      key: 'actor',
      label: 'Actor',
      render: (item) => {
        const userId = getString(item, ['actor_user_id'], '');
        const role = getString(item, ['actor_role'], '');
        return (
          <span className="cp-stack">
            <span>{userId && userId !== '—' ? userId : 'Not recorded'}</span>
            <span className="muted small">{role && role !== '—' ? plainCodeLabel(role) : 'Role not recorded'}</span>
          </span>
        );
      }
    },
    { key: 'action', label: 'Action', render: (item) => <span title={getString(item, ['action'], '')}>{formatAuditAction(getString(item, ['action']), 'Unknown action', item.metadata)}</span> },
    { key: 'resource', label: 'Resource', render: resourceCell },
    {
      key: 'hash',
      label: 'Recorded hash',
      render: (item) => {
        const short = formatAuditHash(item);
        return short ? <span className="mono muted" title={getString(item, ['entry_hash'])}>{short}</span> : <span className="muted">Not recorded</span>;
      }
    }
  ];

  const resourceRoute = selectedEntry ? AUDIT_RESOURCE_ROUTES[getString(selectedEntry, ['resource_type'], '')] : '';
  const selectedResourceId = selectedEntry ? getString(selectedEntry, ['resource_id'], '') : '';
  const presentValue = (value: string) => (value && value !== '—' ? value : '');
  const selectedActorId = selectedEntry ? presentValue(getString(selectedEntry, ['actor_user_id'], '')) : '';
  const selectedActionKey = selectedEntry ? presentValue(getString(selectedEntry, ['action'], '')) : '';
  const selectedResourceType = selectedEntry ? presentValue(getString(selectedEntry, ['resource_type'], '')) : '';
  const selectedResourceFilter = selectedEntry && sensitiveResourceLabel(selectedResourceType)
    ? selectedResourceType
    : presentValue(selectedResourceId) || selectedResourceType;
  const pageNumber = cursorStack.length;
  const totalText = listState.total === null ? 'total not returned' : `${formatNumber(listState.total)} matching`;

  return (
    <div className="content audit-page">
      <CustomerPageStyles />
      <PageHeader
        route="audit"
        title="Audit log"
        description="Who did what, when, and to which resource. Entries are append-only and hash-chained. Each export includes every entry's hash and previous hash so the chain can be checked offline. This page does not verify the hash chain."
        actions={allowed ? (
          <Button
            size="sm"
            variant="secondary"
            loading={exportState.status === 'loading'}
            disabled={Boolean(exportDisabledReason) || exportState.status === 'loading'}
            title={exportDisabledReason || undefined}
            aria-describedby={exportDisabledReason ? 'audit-export-reason' : undefined}
            onClick={() => void exportFilteredEvents()}
          >
            Export filtered events
          </Button>
        ) : undefined}
      />
      {!allowed ? (
        <EmptyState icon={Lock} title="Audit access required." body="Owners, admins, SOC, and auditors can read the audit log. Your role cannot, so no events are shown." />
      ) : (
        <>
          <PageContextSummary>
            {listState.status === 'ready' ? <>{totalText}{filtersActive ? ' for the applied filters' : ''} · page {formatNumber(pageNumber)}, newest first</> : listState.status === 'loading' ? 'Loading events…' : 'Events unavailable'}
          </PageContextSummary>
          {exportDisabledReason ? <p className="sr-only" id="audit-export-reason">{exportDisabledReason}</p> : null}
          {exportState.status === 'done' ? <div className="form-banner" role="status" aria-live="polite">{exportState.message}</div> : null}
          {exportState.status === 'error' ? (
            <div className="form-banner error row-actions" role="alert">
              <span>{exportState.message}</span>
              <Button size="sm" variant="secondary" onClick={() => void exportFilteredEvents()}>Retry export</Button>
            </div>
          ) : null}
          <form className="audit-filter-toolbar" role="search" aria-label="Audit filters" onSubmit={applyFilters} noValidate>
            <div className="audit-filter-fields">
              <label className="field">
                <span title={`From (${viewerZone})`}>From ({viewerZone})</span>
                <input type="date" value={draft.since} onChange={(event) => setDraft((current) => ({ ...current, since: event.target.value }))} max={draft.until || undefined} />
              </label>
              <label className="field">
                <span title={`To (${viewerZone})`}>To ({viewerZone})</span>
                <input type="date" value={draft.until} onChange={(event) => setDraft((current) => ({ ...current, until: event.target.value }))} min={draft.since || undefined} aria-invalid={dateError ? true : undefined} aria-describedby={dateError ? 'audit-date-error' : undefined} />
              </label>
              <label className="field">
                <span>Actor (user ID)</span>
                <input list="audit-actor-options" value={draft.actor} onChange={(event) => setDraft((current) => ({ ...current, actor: event.target.value }))} placeholder="Exact user ID" autoComplete="off" spellCheck={false} aria-describedby="audit-filter-help" />
                <datalist id="audit-actor-options">{actorOptions.map(([value, role]) => <option key={value} value={value} label={role} />)}</datalist>
              </label>
              <label className="field">
                <span>Action</span>
                <input list="audit-action-options" value={draft.action} onChange={(event) => setDraft((current) => ({ ...current, action: event.target.value }))} placeholder="Choose or type an action" autoComplete="off" spellCheck={false} aria-describedby="audit-filter-help" />
                <datalist id="audit-action-options">{actionOptions.map((value) => <option key={value} value={value} label={formatAuditAction(value)} />)}</datalist>
              </label>
              <label className="field">
                <span>Resource type or ID</span>
                <input list="audit-resource-options" value={draft.resource} onChange={(event) => setDraft((current) => ({ ...current, resource: event.target.value }))} placeholder="e.g. Target or tgt_123" autoComplete="off" spellCheck={false} aria-describedby="audit-filter-help" />
                <datalist id="audit-resource-options">{resourceOptions.map((value) => <option key={value} value={value} label={formatResourceTypeLabel(value)} />)}</datalist>
              </label>
            </div>
            {dateError ? <p className="field-error" id="audit-date-error" role="alert">{dateError}</p> : null}
            <div className="cp-toolbar">
              <Button type="submit" size="sm">Apply filters</Button>
              {filtersActive ? <Button type="button" size="sm" variant="ghost" onClick={clearFilters}>Clear filters</Button> : null}
              <span className="muted small" id="audit-filter-help">Type the action or resource as shown, or its key; filters match exactly. Dates are whole days in your timezone.</span>
            </div>
          </form>
          {selectedId && !selectedEntry ? (
            <div className={exact.status === 'error' ? 'form-banner error row-actions' : 'form-banner neutral'} role="status">
              <span>
                Event {selectedId}{' '}
                {exact.id !== selectedId || exact.status === 'loading' || exact.status === 'idle' || listState.status === 'loading' ? 'is being looked up by its exact ID…'
                  : exact.status === 'not_found' ? 'does not exist in this workspace. Nothing else was selected in its place.'
                    : exact.status === 'denied' ? 'is not readable with your role.'
                      : 'could not be looked up. Nothing else was selected in its place.'}
              </span>
              {exact.status === 'error' ? <Button size="sm" variant="secondary" onClick={() => setExactTick((count) => count + 1)}>Retry lookup</Button> : null}
            </div>
          ) : null}
          {selectedEntry ? (
            <Card density="compact" raised>
              <section id="audit-event-detail" tabIndex={-1} aria-label="Selected audit event" className="audit-event-detail">
                <CardHeader>
                  <div>
                    <CardTitle>{formatAuditAction(getString(selectedEntry, ['action']), 'Unknown action', selectedEntry.metadata)}</CardTitle>
                    <CardDescription>{auditTimestamp(selectedEntry) ? formatDate(auditTimestamp(selectedEntry)) : 'Time not recorded'} · {formatResourceTypeLabel(getString(selectedEntry, ['resource_type'], 'resource'))}</CardDescription>
                  </div>
                  <Button size="sm" variant="ghost" onClick={() => setSelectedId('')}>Close</Button>
                </CardHeader>
                <CardContent className="stack-tight">
                  {selectedOffPage ? <p className="muted small">Loaded by exact ID; it is not on the current page of results.</p> : null}
                  <div className="kv-list">
                    <KvField label="Actor">{getString(selectedEntry, ['actor_user_id'], 'Not recorded')} ({plainCodeLabel(getString(selectedEntry, ['actor_role'], 'role not recorded'))})</KvField>
                    <KvField label="Resource">
                      {(() => {
                        const sensitiveLabel = sensitiveResourceLabel(getString(selectedEntry, ['resource_type'], ''));
                        if (sensitiveLabel) return sensitiveLabel;
                        if (resourceRoute && selectedResourceId && selectedResourceId !== '—') {
                          return <a className="cp-link" href={buildDetailHref(resourceRoute, selectedResourceId)}>{selectedResourceId}</a>;
                        }
                        return selectedResourceId || 'Not recorded';
                      })()}
                    </KvField>
                    <KvField label="Event time">{auditTimestamp(selectedEntry) ? formatDate(auditTimestamp(selectedEntry)) : 'Not recorded'}</KvField>
                    <KvField label="Event ID"><span className="cp-mono-wrap">{getString(selectedEntry, ['id'], 'Not recorded')}</span></KvField>
                    <KvField label="Sequence">{getString(selectedEntry, ['sequence'], 'Not recorded')}</KvField>
                    <KvField label="Recorded hash"><span className="cp-mono-wrap">{getString(selectedEntry, ['entry_hash'], 'Not recorded')}</span></KvField>
                    <KvField label="Previous hash"><span className="cp-mono-wrap">{getString(selectedEntry, ['prev_hash'], 'Not recorded')}</span></KvField>
                    {selectedEntry.metadata && typeof selectedEntry.metadata === 'object' && !Array.isArray(selectedEntry.metadata) && isFlatMetadataObject(selectedEntry.metadata)
                      ? Object.entries(selectedEntry.metadata).map(([key, value]) => (
                        <KvField key={key} label={plainCodeLabel(key)}>{value === null ? 'Not recorded' : String(value)}</KvField>
                      ))
                      : selectedEntry.metadata && typeof selectedEntry.metadata === 'object'
                        ? <KvField label="Recorded change">Structured; open the technical record below.</KvField>
                        : <KvField label="Recorded change">No metadata recorded</KvField>}
                  </div>
                  <p className="muted small">This records that the action happened. Whether the resulting configuration works is shown by evidence on the resource itself.</p>
                  <div className="row-actions" role="group" aria-label="Filter the log to this event's values">
                    <Button size="sm" variant="ghost" disabled={!selectedActorId} onClick={() => filterTo('actor', selectedActorId)}>Filter to this actor</Button>
                    <Button size="sm" variant="ghost" disabled={!selectedActionKey} onClick={() => filterTo('action', selectedActionKey)}>Filter to this action</Button>
                    <Button size="sm" variant="ghost" disabled={!selectedResourceFilter} onClick={() => filterTo('resource', selectedResourceFilter)}>Filter to this resource</Button>
                  </div>
                  <div className="row-actions">
                    <Button
                      size="sm"
                      variant="secondary"
                      onClick={() => {
                        const href = `${window.location.origin}${window.location.pathname}#audit?event=${encodeURIComponent(getString(selectedEntry, ['id'], ''))}`;
                        void navigator.clipboard.writeText(href).then(() => setCopyNotice('Event link copied.')).catch(() => setCopyNotice('Copy failed; select the event ID above.'));
                      }}
                    >
                      Copy event link
                    </Button>
                    <span className="muted small" aria-live="polite">{copyNotice}</span>
                  </div>
                  {selectedEntry.metadata && typeof selectedEntry.metadata === 'object' ? (() => {
                    const metadataJson = JSON.stringify(selectedEntry.metadata, null, 2);
                    const downloadId = getString(selectedEntry, ['id', 'audit_id'], 'audit-entry');
                    return (
                      <ExpandableCodePanel
                        panelId="audit-raw-metadata-panel"
                        expanded={showRawAuditMetadata}
                        onToggle={() => setShowRawAuditMetadata((open) => !open)}
                        toggleLabels={{ show: 'Show technical record', hide: 'Hide technical record' }}
                        code={metadataJson.slice(0, 1800)}
                        truncated={metadataJson.length > 1800}
                        downloadLabel="Download full metadata"
                        onDownload={() => downloadJsonFile(`audit-metadata-${downloadId}.json`, selectedEntry.metadata)}
                      />
                    );
                  })() : null}
                </CardContent>
              </section>
            </Card>
          ) : null}
          <Card>
            <CardHeader>
              <CardTitle>Events</CardTitle>
              <CardDescription>Select an event to see its recorded change. The selection is kept in the address so it can be shared.</CardDescription>
            </CardHeader>
            <CardContent className="stack-tight">
              {listState.status === 'loading' && items.length === 0 ? <PortalLoadingSkeleton rows={4} label="Loading audit events" /> : (
                <DataTable
                  columns={columns}
                  items={items}
                  selectedId={selectedId || null}
                  getRowId={(item) => auditEntrySelectionKey(item)}
                  getRowProps={(item) => {
                    const key = auditEntrySelectionKey(item);
                    const sensitiveLabel = sensitiveResourceLabel(getString(item, ['resource_type'], ''));
                    const resourceLabel = sensitiveLabel ?? getString(item, ['resource_id', 'resource_type'], 'unknown resource');
                    return {
                      onClick: () => setSelectedId(key),
                      onKeyDown: (event) => {
                        if (event.key !== 'Enter' && event.key !== ' ') return;
                        event.preventDefault();
                        setSelectedId(key);
                      },
                      tabIndex: 0,
                      'aria-label': `Inspect ${formatAuditAction(getString(item, ['action'], 'audit event'), 'audit event', item.metadata)} on ${resourceLabel}`
                    };
                  }}
                  empty={filtersActive
                    ? <EmptyState icon={ClipboardList} title="No events match these filters." body="The server found no event for the applied filters. Clear them to see every event." actionLabel="Clear filters" onAction={clearFilters} />
                    : <EmptyState icon={ClipboardList} title="No audit events recorded yet." body="Security-relevant actions such as target, schedule, report, and credential changes are recorded here as they happen." />}
                  loadError={listState.status === 'error' ? listState.error : null}
                  onRetry={() => { setReloadTick((count) => count + 1); void onRefresh?.(); }}
                />
              )}
              {listState.status === 'ready' && (cursorStack.length > 1 || listState.nextCursor) ? (
                <nav className="cp-toolbar" aria-label="Audit pages">
                  <span className="muted small">Page {formatNumber(pageNumber)} · {formatNumber(items.length)} {pluralize(items.length, 'event')} on this page · {totalText}</span>
                  <Button size="sm" variant="secondary" disabled={cursorStack.length <= 1} onClick={() => setCursorStack((current) => current.slice(0, -1))}>Newer</Button>
                  <Button size="sm" variant="secondary" disabled={!listState.nextCursor} onClick={() => setCursorStack((current) => [...current, listState.nextCursor])}>Older</Button>
                </nav>
              ) : null}
            </CardContent>
          </Card>
        </>
      )}
    </div>
  );
}

type ReleaseRecordView = {
  key: string;
  item: DataItem;
  kind: string;
  accepted: boolean;
  acceptance: string;
  validity: 'valid' | 'invalid' | 'not_recorded';
  missingFields: string[];
  forbiddenFields: string[];
  custodyUri: string;
};

function releaseRecordView(item: DataItem, index: number): ReleaseRecordView {
  const status = getString(item, ['status'], '').toLowerCase();
  const validation = getNestedItem(item, ['validation']) ?? null;
  const missingFields = Array.isArray(validation?.missing_fields) ? (validation!.missing_fields as unknown[]).map(String) : [];
  const forbiddenFields = Array.isArray(validation?.forbidden_fields) ? (validation!.forbidden_fields as unknown[]).map(String) : [];
  return {
    key: getString(item, ['id'], `${getString(item, ['kind'], 'record')}-${index}`),
    item,
    kind: getString(item, ['kind'], 'unknown'),
    accepted: status === 'accepted' || status === 'approved',
    acceptance: status || 'not recorded',
    validity: !validation ? 'not_recorded' : validation.ok === true ? 'valid' : 'invalid',
    missingFields,
    forbiddenFields,
    custodyUri: pickReleaseEvidenceCustodyUri(getNestedItem(item, ['evidence']) ?? (item.evidence as DataItem | undefined)) ?? ''
  };
}

export function ReleaseEvidencePage({ data, session }: { data: PortalData; session: Session }) {
  const [clipboardNotice, setClipboardNotice] = useState('');
  const [selectedKey, setSelectedKey] = useState('');
  const [missingQuery, setMissingQuery] = useState('');
  const [recordFilter, setRecordFilter] = useState<'all' | 'problems'>('all');
  const allowed = canReadReleaseEvidence(session.role);
  const attestation = data.releaseAttestation;
  const coverage = computeReleaseEvidenceCoverage(data.releaseEvidence);
  const records = data.releaseEvidence
    .slice()
    .sort((left, right) => new Date(String(right.created_at ?? '')).getTime() - new Date(String(left.created_at ?? '')).getTime())
    .map(releaseRecordView);
  const acceptedInvalid = records.filter((record) => record.accepted && record.validity === 'invalid');
  const acceptedValidKinds = new Set(records.filter((record) => record.accepted && record.validity === 'valid').map((record) => record.kind));
  const visibleRecords = recordFilter === 'problems' ? records.filter((record) => !record.accepted || record.validity !== 'valid') : records;
  const selected = records.find((record) => record.key === selectedKey) ?? null;
  const signoff = getNestedString(attestation, ['signoff_status'], '');
  const missingFiltered = coverage.missing.filter((kind) => `${kind} ${plainCodeLabel(kind)}`.toLowerCase().includes(missingQuery.trim().toLowerCase()));

  const missingKindColumns: TableColumn<{ kind: string }>[] = [
    { key: 'kind', label: 'Required kind', render: (item) => <span title={item.kind}>{plainCodeLabel(item.kind)}</span> }
  ];
  const columns: TableColumn<ReleaseRecordView>[] = [
    { key: 'kind', label: 'Kind', render: (record) => <span title={record.kind}>{plainCodeLabel(record.kind)}</span> },
    { key: 'acceptance', label: 'Attached', render: (record) => <Badge tone="muted">{record.accepted ? 'Accepted' : formatGovernanceStatusLabel(record.acceptance, 'Not recorded')}</Badge> },
    {
      key: 'validity',
      label: 'Contract validity',
      render: (record) => record.validity === 'valid'
        ? <Badge tone="success">Valid</Badge>
        : record.validity === 'invalid'
          ? <Badge tone="danger">{record.accepted ? 'Accepted but invalid' : 'Invalid'}</Badge>
          : <Badge tone="muted">Not validated</Badge>
    },
    { key: 'custody', label: 'Custody reference', render: (record) => record.custodyUri ? <span className="muted small">Reference recorded, not verified</span> : <span className="muted small">None</span> },
    { key: 'created', label: 'Recorded', render: (record) => <span className="mono">{formatDate(record.item.created_at)}</span> }
  ];

  function gapLedgerTechnicalPayload() {
    return {
      exported_at: new Date().toISOString(),
      tenant_id: session.tenant_id ?? data.state?.tenant_id ?? 'unknown',
      profile: getNestedString(attestation, ['profile'], 'not recorded'),
      coverage,
      accepted_invalid: acceptedInvalid.map((record) => ({ kind: record.kind, missing_fields: record.missingFields, forbidden_fields: record.forbiddenFields })),
      attestation,
      records: records.map((record) => ({
        kind: record.kind,
        status: record.acceptance,
        validation: summarizeReleaseEvidenceValidation(getNestedItem(record.item, ['validation']) ?? null),
        custody_uri: record.custodyUri || null
      }))
    };
  }

  function copyGapLedgerSummary() {
    const summary = [
      `Release evidence gap ledger · workspace ${session.tenant_id ?? data.state?.tenant_id ?? 'unknown'} · profile ${getNestedString(attestation, ['profile'], 'not recorded')}`,
      `Accepted records cover ${coverage.recorded} of ${coverage.expected} required kinds; ${acceptedValidKinds.size} of those kinds have a contract-valid record.`,
      coverage.missing.length > 0 ? `Missing kinds (${coverage.missing.length}): ${coverage.missing.join(', ')}.` : 'No required kind is missing an accepted record.',
      acceptedInvalid.length > 0 ? `Accepted but failing contract validation (${acceptedInvalid.length}): ${acceptedInvalid.map((record) => record.kind).join(', ')}.` : 'No accepted record fails contract validation.',
      `External signoff: ${signoff || 'not recorded'}. Operator production-ready flag: ${String(attestation?.production_ready ?? 'not recorded')}.`,
      'Inventory completeness and contract validity are not customer launch approval.',
      `Copied ${new Date().toISOString()}.`
    ].join('\n');
    void navigator.clipboard.writeText(summary)
      .then(() => setClipboardNotice('Gap summary copied.'))
      .catch(() => setClipboardNotice('Could not copy the gap summary.'));
  }

  return (
    <div className="content release-evidence-page">
      <CustomerPageStyles />
      <PageHeader
        route="release-evidence"
        title="Release evidence"
        description="Which required release evidence is attached, which of it passes contract validation, and whether external signoff is recorded. These are separate; none of them alone approves a customer launch."
      />
      {!allowed ? (
        <EmptyState icon={FileText} title="Release evidence access required." body="Owners, admins, SOC, and auditors can read release evidence. Your role cannot." />
      ) : (
        <>
          <div className="kpi-row" role="group" aria-label="Release evidence dimensions">
            <KpiCell
              label="Inventory"
              value={`${formatNumber(coverage.recorded)} of ${formatNumber(coverage.expected)}`}
              delta={`required kinds have an accepted record · ${formatNumber(coverage.missing.length)} missing`}
            />
            <KpiCell
              label="Contract validity"
              value={`${formatNumber(acceptedValidKinds.size)} of ${formatNumber(coverage.expected)}`}
              delta={acceptedInvalid.length > 0 ? `${formatNumber(acceptedInvalid.length)} accepted record${acceptedInvalid.length === 1 ? ' fails' : 's fail'} validation` : 'kinds have a contract-valid accepted record'}
            />
            <KpiCell
              label="External signoff"
              value={signoff ? formatGovernanceStatusLabel(signoff) : 'Not recorded'}
              delta={`Operator attestation${attestation?.checked_at || attestation?.created_at ? ` checked ${formatDate(attestation?.checked_at ?? attestation?.created_at)}` : ', time not recorded'}`}
            />
            <KpiCell
              label="Profile"
              value={formatGovernanceStatusLabel(getNestedString(attestation, ['profile'], ''), 'Not recorded')}
              delta={`Production-ready flag: ${productionReadyLabel(attestation?.production_ready)}`}
            />
          </div>
          {clipboardNotice ? <GovernanceInfoBanner>{clipboardNotice}</GovernanceInfoBanner> : null}
          {data.loadErrors.releaseEvidence ? (
            <div className="form-banner error" role="alert">Release evidence could not be loaded: {data.loadErrors.releaseEvidence}. Missing kinds below are unknown, not confirmed missing.</div>
          ) : null}
          <div className={selected ? 'release-ledger has-selection' : 'release-ledger'}>
            <Card>
              <PanelCardHeader
                title="Attached records"
                description="Select a record to see why it passes or fails."
                trailing={(
                  <div className="cp-toolbar" role="group" aria-label="Filter records">
                    <button type="button" className={`filter-chip${recordFilter === 'all' ? ' is-active' : ''}`} aria-pressed={recordFilter === 'all'} onClick={() => setRecordFilter('all')}>All {formatNumber(records.length)}</button>
                    <button type="button" className={`filter-chip${recordFilter === 'problems' ? ' is-active' : ''}`} aria-pressed={recordFilter === 'problems'} onClick={() => setRecordFilter('problems')}>Needs attention {formatNumber(records.filter((record) => !record.accepted || record.validity !== 'valid').length)}</button>
                  </div>
                )}
              />
              <CardContent>
                <DataTable
                  columns={columns}
                  items={visibleRecords}
                  getRowId={(record) => record.key}
                  selectedId={selectedKey || null}
                  getRowProps={(record) => ({
                    tabIndex: 0,
                    'aria-label': `Inspect ${plainCodeLabel(record.kind)} record`,
                    onClick: () => setSelectedKey(record.key),
                    onKeyDown: (event) => {
                      if (event.key !== 'Enter' && event.key !== ' ') return;
                      event.preventDefault();
                      setSelectedKey(record.key);
                    }
                  })}
                  empty={<EmptyState icon={FileText} title={recordFilter === 'problems' ? 'No records need attention.' : 'No release evidence attached.'} body={recordFilter === 'problems' ? 'Every attached record is accepted and contract-valid.' : 'Records appear after an operator attaches them. Rehearsal fixtures do not establish production readiness.'} />}
                  loadError={data.loadErrors.releaseEvidence}
                />
              </CardContent>
            </Card>
            {selected ? (
              <Card className="release-record-detail" raised>
                <section aria-label={`${plainCodeLabel(selected.kind)} record detail`}>
                  <CardHeader>
                    <div>
                      <CardTitle>{plainCodeLabel(selected.kind)}</CardTitle>
                      <CardDescription><code>{selected.kind}</code> · recorded {formatDate(selected.item.created_at)}</CardDescription>
                    </div>
                    <Button size="sm" variant="ghost" onClick={() => setSelectedKey('')}>Close</Button>
                  </CardHeader>
                  <CardContent className="stack-tight">
                    <div className="kv-list">
                      <KvField label="Attached">{selected.accepted ? 'Accepted into the inventory' : formatGovernanceStatusLabel(selected.acceptance, 'Not recorded')}</KvField>
                      <KvField label="Contract validity">{selected.validity === 'valid' ? 'Valid against the evidence contract (metadata only)' : selected.validity === 'invalid' ? 'Fails the evidence contract' : 'Not validated'}</KvField>
                      <KvField label="Custody">{selected.custodyUri ? 'Reference recorded; not verified here' : 'No custody reference'}</KvField>
                      <KvField label="Release">{getString(selected.item, ['release_id', 'id'], 'Not recorded')}</KvField>
                    </div>
                    {selected.validity === 'invalid' ? (
                      <div className="form-banner error" role="note">
                        <strong>Why it fails{selected.accepted ? ' even though it was accepted' : ''}:</strong>
                        {selected.missingFields.length ? <> missing {selected.missingFields.join(', ')}.</> : null}
                        {selected.forbiddenFields.length ? <> forbidden {selected.forbiddenFields.join(', ')}.</> : null}
                        {!selected.missingFields.length && !selected.forbiddenFields.length ? ' the validator recorded no field-level reason.' : null}
                        {' '}It does not count as passing evidence.
                      </div>
                    ) : null}
                    {selected.custodyUri ? (
                      <div className="row-actions">
                        <code className="cp-mono-wrap">{selected.custodyUri}</code>
                        <Button
                          size="sm"
                          variant="ghost"
                          aria-label="Copy custody reference"
                          onClick={() => {
                            void navigator.clipboard.writeText(selected.custodyUri).then(() => setClipboardNotice('Custody reference copied.')).catch(() => setClipboardNotice('Could not copy the custody reference.'));
                          }}
                        >
                          <Copy size={14} aria-hidden="true" />
                        </Button>
                      </div>
                    ) : null}
                    <p className="muted small">Valid metadata is not customer launch approval. External signoff is tracked separately above.</p>
                  </CardContent>
                </section>
              </Card>
            ) : null}
          </div>
          <Card>
            <PanelCardHeader
              title={`Missing kinds (${formatNumber(coverage.missing.length)})`}
              description="Every required kind without an accepted record. Owners are not recorded in the evidence contract."
              trailing={(
                <div className="row-actions">
                  <Button size="sm" variant="secondary" onClick={copyGapLedgerSummary}>Copy gap summary</Button>
                  <Button size="sm" variant="secondary" onClick={() => downloadJsonFile(`release-evidence-gap-ledger-${session.tenant_id ?? 'tenant'}.json`, gapLedgerTechnicalPayload())}>Download JSON</Button>
                </div>
              )}
            />
            <CardContent className="stack-tight">
              {coverage.missing.length > 8 ? (
                <label className="audit-search-pill">
                  <Search size={15} aria-hidden="true" />
                  <input type="search" value={missingQuery} onChange={(event) => setMissingQuery(event.target.value)} placeholder="Filter missing kinds" aria-label="Filter missing kinds" />
                </label>
              ) : null}
              <DataTable
                columns={missingKindColumns}
                items={missingFiltered.map((kind) => ({ kind }))}
                getRowId={(item) => item.kind}
                empty={coverage.missing.length === 0
                  ? <EmptyState icon={CheckCircle2} title="No required kind is missing." body="Every required kind has an accepted record. Check contract validity and signoff separately." />
                  : <EmptyState icon={Search} title="No missing kind matches." body="Clear the filter to see all missing kinds." actionLabel="Clear filter" onAction={() => setMissingQuery('')} />}
              />
            </CardContent>
          </Card>
          {data.loadErrors.releaseAttestation ? (
            <div className="form-banner error" role="alert">Attestation could not be loaded: {data.loadErrors.releaseAttestation}. Signoff status above is unknown.</div>
          ) : null}
        </>
      )}
    </div>
  );
}

export function SocConsolePage({
  data,
  config,
  session,
  onRefresh,
  staffSocSurface: requestedStaffSocSurface = false
}: {
  data: PortalData;
  config: PortalConfig;
  session: Session;
  onRefresh: () => Promise<void>;
  staffSocSurface?: boolean;
}) {
  // The staff cross-tenant plane is only ever rendered for a staff principal.
  // The router requests it for the shared `internal-soc` route, but a customer
  // `soc` principal (SOC-01) must land on the tenant-scoped console instead of
  // the "Staff SOC role required" wall. Downgrading here keeps route/surface
  // logic clean without widening what a customer session can read.
  const staffSocSurface = requestedStaffSocSurface && session.principal === 'staff';
  const { confirm } = useConfirmModal();
  const [busy, setBusy] = useState('');
  const [queueRefreshing, setQueueRefreshing] = useState(false);
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');
  const [stoppedRequestIds, setStoppedRequestIds] = useState<string[]>([]);
  const [output, setOutput] = useState('');
  const [outputSummary, setOutputSummary] = useState('');
  const [showActionTechnicalDetails, setShowActionTechnicalDetails] = useState(false);
  const [lastActionRequestId, setLastActionRequestId] = useState('');
  const [executionTenantId, setExecutionTenantId] = useState(() => getRouteTenantId(session.tenant_id ?? '').trim());
  const [killSwitchReasonDraft, setKillSwitchReasonDraft] = useState('');
  const [killSwitchFocusPending, setKillSwitchFocusPending] = useState(false);
  const killSwitchCardRef = useRef<HTMLDivElement>(null);
  const killSwitchReasonRef = useRef<HTMLTextAreaElement>(null);

  function setActionOutput(payload: unknown, requestId = '') {
    setOutput(JSON.stringify(payload, null, 2));
    setOutputSummary(summarizeSocActionPayload(payload));
    setShowActionTechnicalDetails(false);
    setLastActionRequestId(requestId);
  }

  function resetFeedback() {
    setError('');
    setMessage('');
    setStoppedRequestIds([]);
  }

  const isSoc = staffSocSurface
    ? session.principal === 'staff' && isStaffSocRole(session)
    : session.principal !== 'staff';
  const effectiveSocTenant = executionTenantId || String(session.tenant_id ?? '').trim();
  const [socQueue, setSocQueue] = useState<{ items: DataItem[]; tenants: DataItem[]; error: string }>({ items: [], tenants: [], error: '' });
  const [socQueueRevision, setSocQueueRevision] = useState(0);
  const staffIdentity = `${session.principal ?? ''}:${session.staff_id ?? ''}:${session.staff_role ?? ''}:${session.access_token ?? ''}`;

  useEffect(() => {
    if (!staffSocSurface || !isSoc) return undefined;
    let cancelled = false;
    requestJson(config, session, '/internal/admin/soc/high-scale-requests')
      .then((payload) => {
        if (cancelled) return;
        const body = (payload ?? {}) as { items?: unknown; tenants?: unknown };
        setSocQueue({
          items: Array.isArray(body.items) ? (body.items as DataItem[]) : [],
          tenants: Array.isArray(body.tenants) ? (body.tenants as DataItem[]) : [],
          error: ''
        });
      })
      .catch((err: unknown) => {
        if (!cancelled) setSocQueue({ items: [], tenants: [], error: apiErrorMessage(err, 'Cross-tenant high-scale requests could not be loaded.') });
      });
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [staffSocSurface, isSoc, staffIdentity, socQueueRevision]);

  async function refreshSocConsole() {
    setSocQueueRevision((value) => value + 1);
    await onRefresh();
  }

  async function applyExecutionTenant(tenantId: string) {
    const nextTenant = tenantId.trim();
    if (nextTenant !== effectiveSocTenant) setKillSwitchReasonDraft('');
    setExecutionTenantId(nextTenant);
    if (!staffSocSurface) return;
    const nextSession = { ...session, tenant_id: nextTenant || undefined };
    saveSession(nextSession);
    resetFeedback();
    setMessage(nextTenant ? `Execution tenant set to ${tenantDisplayName(nextTenant)}.` : 'Execution tenant cleared.');
    setQueueRefreshing(true);
    try {
      await onRefresh();
    } finally {
      setQueueRefreshing(false);
    }
  }

  function prepareKillSwitchFor(tenantId: string) {
    setKillSwitchFocusPending(true);
    if (tenantId !== effectiveSocTenant) void applyExecutionTenant(tenantId);
  }

  useEffect(() => {
    setKillSwitchReasonDraft('');
  }, [effectiveSocTenant]);

  useEffect(() => {
    if (!killSwitchFocusPending || !effectiveSocTenant) return;
    setKillSwitchFocusPending(false);
    killSwitchCardRef.current?.scrollIntoView({ block: 'center', behavior: prefersReducedMotion() ? 'auto' : 'smooth' });
    killSwitchReasonRef.current?.focus({ preventScroll: true });
  }, [killSwitchFocusPending, effectiveSocTenant]);

  async function socRequest(path: string, options: { method?: string; body?: unknown; tenantId?: string } = {}) {
    if (staffSocSurface) {
      const tenantId = options.tenantId ?? effectiveSocTenant;
      if (!tenantId) {
        throw new Error('Select an execution tenant before running staff SOC actions.');
      }
      return requestSocJson(config, session, path, {
        method: options.method,
        body: options.body,
        tenantId
      });
    }
    return requestJson(config, session, path, options);
  }

  const tenantNames = useMemo(() => {
    const names = new Map<string, string>();
    for (const tenant of socQueue.tenants) {
      const id = getString(tenant, ['tenant_id'], '');
      const name = getString(tenant, ['name'], '');
      if (id && name) names.set(id, name);
    }
    for (const item of socQueue.items) {
      const id = getString(item, ['tenant_id'], '');
      const name = getString(item, ['tenant_name'], '');
      if (id && name && !names.has(id)) names.set(id, name);
    }
    return names;
  }, [socQueue.items, socQueue.tenants]);

  function tenantDisplayName(tenantId: string) {
    return socTenantLabel(tenantNames.get(tenantId) ?? '', tenantId);
  }

  const requestColumns: TableColumn<DataItem>[] = [
    { key: 'id', label: 'Request', render: (item) => { const id = getString(item, ['id'], ''); return <span title={id || undefined}>{getString(item, ['objective', 'reason', 'name'], 'High-scale validation request')}</span>; } },
    {
      key: 'state',
      label: 'State',
      render: (item) => {
        const state = getString(item, ['state']);
        return <Badge tone={highScaleStateTone(state)}>{formatGovernanceStatusLabel(state, 'Unknown')}</Badge>;
      }
    },
    {
      key: 'window',
      label: 'Window',
      render: (item) => (
        <SocWindowCell
          start={getNestedString(item, ['scheduled_window', 'window_start'], '')}
          end={getNestedString(item, ['scheduled_window', 'window_end'], '')}
          state={normalizeHighScaleState(item)}
        />
      )
    },
    {
      key: 'target',
      label: 'Domains',
      render: (item) => {
        const domains = requestDomainDisplay(data, item);
        return domains.length ? domains.join(', ') : <span className="muted">Domain scope not recorded</span>;
      }
    },
    {
      key: 'pack',
      label: 'Pack',
      render: (item) => {
        const pack = authorizationPackSummary(item);
        return <Badge tone={authorizationPackBadgeTone(pack.overall)} title={pack.detail}>{pack.label}</Badge>;
      }
    },
    {
      key: 'limits',
      label: 'Governed limits',
      render: (item) => <span className="mono">{governedLimitDisplay(item)}</span>
    },
    {
      key: 'provider',
      label: 'Provider approval',
      render: (item) => {
        const provider = providerApprovalSummary(item);
        return <Badge tone={provider.tone} title={provider.detail}>{provider.label}</Badge>;
      }
    },
    {
      key: 'actions',
      label: 'Actions',
      render: (item) => {
        const id = getString(item, ['id'], '');
        const state = normalizeHighScaleState(item);
        const reviewable = ['submitted', 'under_review'].includes(state);
        const executionTenantMissing = staffSocSurface && !effectiveSocTenant;
        const approvalDisabled = executionTenantMissing
          ? { full: 'Select an execution tenant before approving this request.', short: 'Select a tenant' }
          : null;
        const approvalControlId = `quick-approve-reason-${id}`;
        return (
          <div className="stack-tight">
            <AnchorButton
              size="sm"
              variant="secondary"
              href={buildDetailHref('queue-detail', id, staffSocSurface && effectiveSocTenant ? { tenantId: effectiveSocTenant } : undefined)}
            >Open</AnchorButton>
            {reviewable ? (
              <>
                <Button
                  size="sm"
                  variant="secondary"
                  loading={busy === `approve-${id}`}
                  disabled={Boolean(approvalDisabled) || (busy !== '' && busy !== `approve-${id}`)}
                  title={approvalDisabled?.full || (busy && busy !== `approve-${id}` ? 'Another SOC action is in progress.' : undefined)}
                  aria-describedby={approvalDisabled ? approvalControlId : undefined}
                  onClick={(clickEvent) => {
                    clickEvent.stopPropagation();
                    void socAction(item, 'approve');
                  }}
                >
                  Quick approve
                </Button>
                {approvalDisabled ? (
                  <span className="muted text-xs">
                    <span aria-hidden="true">{approvalDisabled.short}</span>
                    <span className="sr-only" id={approvalControlId}>{approvalDisabled.full}</span>
                  </span>
                ) : null}
              </>
            ) : null}
          </div>
        );
      }
    }
  ];

  async function socAction(item: DataItem, action: 'approve', body: Record<string, unknown> = {}) {
    const requestId = getString(item, ['id'], '');
    if (!requestId) return null;
    const objective = getString(item, ['objective', 'title', 'reason', 'name'], '');
    const tenantId = staffSocSurface ? effectiveSocTenant : String(session.tenant_id ?? '').trim();
    const subject = objective ? `“${objective}”` : 'this high-scale request';
    if (!(await confirm({
      title: `Approve ${objective ? `“${objective}”` : 'high-scale request'}`,
      description: `Approve ${subject} (${requestId}) for tenant ${tenantDisplayName(tenantId)} and move it to approved? Scheduling and execution remain separate SOC steps behind the authorization pack and safety gates.`,
      confirmLabel: 'Approve request',
      confirmTone: 'default'
    }))) return null;
    setBusy(`${action}-${requestId}`);
    resetFeedback();
    try {
      const payload = await socRequest(`/internal/soc/high-scale/${encodeURIComponent(requestId)}/${action}`, {
        method: 'POST',
        body
      });
      setActionOutput(payload, requestId);
      setMessage(`Approved ${objective || requestId}.`);
      setQueueRefreshing(true);
      try {
        await onRefresh();
      } finally {
        setQueueRefreshing(false);
      }
      return payload;
    } catch (err) {
      setError(apiErrorMessage(err, 'SOC action failed.'));
      return null;
    } finally {
      setBusy('');
    }
  }

  const killSwitchActive = Boolean(data.state?.kill_switch?.active ?? data.state?.kill_switch?.enabled);
  const killSwitchReason = getString(data.state?.kill_switch as DataItem, ['reason'], '');
  const runningCount = data.highScale.filter((item) => SOC_RUNNING_STATES.includes(normalizeHighScaleState(item))).length;
  const killSwitchReasonText = killSwitchReasonDraft.trim();
  const killSwitchReasonShort = killSwitchReasonText.length < KILL_SWITCH_REASON_MIN;

  async function setKillSwitch(active: boolean) {
    const reason = killSwitchReasonText;
    if (reason.length < KILL_SWITCH_REASON_MIN) return;
    const tenantLabel = tenantDisplayName(effectiveSocTenant);
    if (active) {
      if (!await confirm({
        title: `Activate kill switch for ${tenantLabel}`,
        description: `${formatNumber(runningCount)} running high-scale ${pluralize(runningCount, 'request')} will be stopped. New safe runs will be blocked and active safe runs cancelled for this tenant. Reason: ${reason}`,
        confirmLabel: 'Activate kill switch'
      })) return;
    } else if (!await confirm({
      title: `Clear kill switch for ${tenantLabel}`,
      description: `Execution remains subject to authorization packs, approved windows, and all other safety gates. Reason: ${reason}`,
      confirmLabel: 'Clear kill switch',
      confirmTone: 'default'
    })) return;
    setBusy(active ? 'kill-on' : 'kill-off');
    resetFeedback();
    try {
      const payload = await socRequest('/internal/soc/kill-switch', {
        method: 'POST',
        body: { active, reason }
      });
      setActionOutput(payload, '');
      setMessage(summarizeSocActionPayload(payload));
      setStoppedRequestIds(active && payload && typeof payload === 'object' ? killSwitchIdList(payload as DataItem, 'stopped_request_ids') : []);
      setKillSwitchReasonDraft('');
      setQueueRefreshing(true);
      try {
        await onRefresh();
      } finally {
        setQueueRefreshing(false);
      }
    } catch (err) {
      setError(apiErrorMessage(err, 'Kill switch action failed.'));
    } finally {
      setBusy('');
    }
  }

  const openFindingsCount = Number(data.state?.open_findings ?? data.findings.filter(isFindingOpen).length) || 0;
  const providerContactRows = buildProviderContactRows(data.highScale);
  const executionTimeline = buildSocExecutionTimeline(data.highScale);
  const crossTenantHighScale = useMemo(
    () => (staffSocSurface ? buildSocCrossTenantRows(socQueue.items) : []),
    [staffSocSurface, socQueue.items]
  );
  const executionTenantMissing = staffSocSurface && !effectiveSocTenant;
  const goNoGoGates = buildSocGoNoGoGates(data.highScale, {
    killSwitchActive,
    runningCount,
    openFindings: openFindingsCount,
    tenantSelected: !executionTenantMissing
  });
  const goNoGoVerdict = socGoNoGoVerdict(goNoGoGates);
  const kpiStates = data.highScale.map(normalizeHighScaleState);
  const scheduledCount = kpiStates.filter((state) => SOC_SCHEDULED_STATES.includes(state)).length;
  const inReviewCount = kpiStates.filter((state) => SOC_REVIEW_STATES.includes(state)).length;
  const crossTenantRequestCount = new Set(crossTenantHighScale.map((row) => row.id)).size;
  const killSwitchReasonRequired = `Enter a reason of at least ${KILL_SWITCH_REASON_MIN} characters; it is recorded in the audit log and shown to the tenant.`;
  const activateKillSwitchReason = executionTenantMissing
    ? 'Select an execution tenant before activating the kill switch.'
    : killSwitchActive
      ? 'The tenant kill switch is already active.'
      : busy && busy !== 'kill-on'
        ? 'Another SOC action is in progress.'
        : killSwitchReasonShort
          ? killSwitchReasonRequired
          : '';
  const clearKillSwitchReason = executionTenantMissing
    ? 'Select an execution tenant before clearing the kill switch.'
    : !killSwitchActive
      ? 'The tenant kill switch is already clear.'
      : busy && busy !== 'kill-off'
        ? 'Another SOC action is in progress.'
        : killSwitchReasonShort
          ? killSwitchReasonRequired
          : '';
  const killSwitchHelp = executionTenantMissing
    ? 'Select an execution tenant before activating or clearing the kill switch.'
    : killSwitchActive
      ? clearKillSwitchReason || activateKillSwitchReason
      : activateKillSwitchReason || clearKillSwitchReason;
  const crossTenantIds = useMemo(
    () => [...new Set(crossTenantHighScale.map((row) => row.tenantId).filter((id) => id && id !== '—'))],
    [crossTenantHighScale]
  );
  const activeTenantCount = crossTenantIds.length;
  const tenantSelectOptions = useMemo(() => {
    const ids = [...new Set([...crossTenantIds, ...tenantNames.keys(), effectiveSocTenant].filter(Boolean))];
    return [
      { value: '', label: 'Select execution tenant…' },
      ...ids.map((id) => ({ value: id, label: socTenantLabel(tenantNames.get(id) ?? '', id) }))
    ];
  }, [crossTenantIds, effectiveSocTenant, tenantNames]);

  const suggestedExecutionTenant = staffSocSurface && isSoc && !effectiveSocTenant && crossTenantIds.length === 1
    ? crossTenantIds[0]
    : '';

  const socCrossTenantColumns: TableColumn<SocCrossTenantRow>[] = [
    {
      key: 'tenant',
      label: 'Tenant',
      render: (item) => (
        <span className="cp-stack">
          <span>{item.tenantName || tenantNames.get(item.tenantId) || 'Name not recorded'}</span>
          <span className="mono muted small">{item.tenantId}</span>
        </span>
      )
    },
    {
      key: 'request',
      label: 'Request',
      render: (item) => <span className="mono" title={item.id}>{tailTruncateId(item.id, 18)}</span>
    },
    {
      key: 'window',
      label: 'Window',
      render: (item) => <SocWindowCell start={item.windowStart} end={item.windowEnd} state={item.state} terminalWarn />
    },
    {
      key: 'state',
      label: 'State',
      render: (item) => <Badge tone={highScaleStateTone(item.state)}>{formatGovernanceStatusLabel(item.state, 'Unknown')}</Badge>
    },
    { key: 'requested', label: 'Requested', render: (item) => formatDate(item.requestedAt) },
    {
      key: 'actions',
      label: 'Actions',
      render: (item) => {
        const tenantKnown = item.tenantId !== '—';
        const selected = tenantKnown && item.tenantId === effectiveSocTenant;
        const tenantLabel = item.tenantName || tenantNames.get(item.tenantId) || item.tenantId;
        return (
          <div className="row-actions">
            <AnchorButton
              size="sm"
              variant="secondary"
              href={buildDetailHref('queue-detail', item.id, {
                tenantId: tenantKnown ? item.tenantId : undefined
              })}
            >
              Open
            </AnchorButton>
            <Button
              size="sm"
              variant="secondary"
              disabled={!tenantKnown || selected}
              title={selected ? 'This tenant is already the execution tenant.' : undefined}
              onClick={() => void applyExecutionTenant(item.tenantId)}
            >
              Work on tenant
            </Button>
            {tenantKnown && isSocRunningState(item.state) ? (
              <Button
                size="sm"
                variant="danger"
                aria-label={`Engage kill switch for ${tenantLabel}`}
                onClick={() => prepareKillSwitchFor(item.tenantId)}
              >
                Kill switch
              </Button>
            ) : null}
          </div>
        );
      }
    }
  ];

  if (!isSoc) {
    return (
      <div className="content">
        <PageHeader
          route="internal-soc"
        />
        <div className="stack-tight">
          <EmptyState
            icon={ShieldCheck}
            title={staffSocSurface ? 'Staff SOC role required.' : 'SOC role required.'}
            body={staffSocSurface
              ? 'Sign in with a staff soc_analyst or soc_lead role to use the governed high-scale execution console.'
              : 'Switch the workspace role to soc to use the governed high-scale execution console.'}
            actionLabel={staffSocSurface ? 'Open staff login' : undefined}
            actionHref={staffSocSurface ? '/internal/admin/login' : undefined}
          />
          <KillSwitchReadOnlyCard
            active={killSwitchActive}
            reason={killSwitchReason}
          />
        </div>
      </div>
    );
  }

  const feedbackBanner = (
    <GovernanceFeedbackBanner message={message} error={error}>
      {stoppedRequestIds.length > 0 ? (
        <span className="cp-toolbar">
          <span>Stopped requests:</span>
          {stoppedRequestIds.map((id) => (
            <a key={id} className="cp-link mono" href={buildDetailHref('queue-detail', id, effectiveSocTenant ? { tenantId: effectiveSocTenant } : {})}>{id}</a>
          ))}
        </span>
      ) : null}
    </GovernanceFeedbackBanner>
  );

  const controls = (
    <>
      {feedbackBanner}
      <div className="dash-grid">
        <Card density="compact">
          <div ref={killSwitchCardRef}>
            <CardHeader>
              <CardTitle>Kill switch</CardTitle>
              <CardDescription>Tenant-scoped emergency stop across bounded safe runs and governed high-scale adapter execution.</CardDescription>
            </CardHeader>
            <CardContent className="stack-tight">
              <div className="kv-list">
                <KvField label="Status">
                  {executionTenantMissing
                    ? <Badge tone="muted">Tenant not selected</Badge>
                    : <Badge tone={killSwitchActive ? 'danger' : 'success'}>{killSwitchActive ? 'Active' : 'Clear'}</Badge>}
                </KvField>
                <KvField label="Reason">{killSwitchReason && !executionTenantMissing ? killSwitchReason : <span className="muted">Not recorded</span>}</KvField>
              </div>
              <label className="field full">
                <span>Reason (recorded in audit and shown to the tenant)</span>
                <textarea
                  ref={killSwitchReasonRef}
                  rows={2}
                  maxLength={KILL_SWITCH_REASON_MAX}
                  value={killSwitchReasonDraft}
                  onChange={(event) => setKillSwitchReasonDraft(event.target.value)}
                  disabled={executionTenantMissing || busy === 'kill-on' || busy === 'kill-off'}
                  placeholder="e.g. Customer reported origin errors during the approved window"
                  aria-describedby="kill-switch-reason-count"
                />
                <span className="muted small" id="kill-switch-reason-count">{formatNumber(killSwitchReasonDraft.length)}/{KILL_SWITCH_REASON_MAX} characters · at least {KILL_SWITCH_REASON_MIN}</span>
              </label>
              <div className="row-actions">
                <Button
                  variant="danger"
                  loading={busy === 'kill-on'}
                  disabled={Boolean(activateKillSwitchReason)}
                  title={activateKillSwitchReason || undefined}
                  aria-describedby={activateKillSwitchReason ? 'kill-switch-disabled-reason' : undefined}
                  onClick={() => void setKillSwitch(true)}
                >Activate kill switch</Button>
                <Button
                  size="sm"
                  variant="secondary"
                  loading={busy === 'kill-off'}
                  disabled={Boolean(clearKillSwitchReason)}
                  title={clearKillSwitchReason || undefined}
                  aria-describedby={clearKillSwitchReason ? 'kill-switch-disabled-reason' : undefined}
                  onClick={() => void setKillSwitch(false)}
                >Clear</Button>
              </div>
              {killSwitchHelp ? (
                <p className="muted text-xs" id="kill-switch-disabled-reason">{killSwitchHelp}</p>
              ) : null}
              <details className="disclosure">
                <summary>What activation does · {KILL_SWITCH_SEQUENCE.length} steps</summary>
                <div className="timeline-list">
                  {KILL_SWITCH_SEQUENCE.map((step, index) => (
                    <div key={step}>
                      <span aria-hidden="true">{index + 1}</span>
                      <div><strong title={step}>{KILL_SWITCH_STEP_LABELS[step]}</strong></div>
                    </div>
                  ))}
                </div>
              </details>
            </CardContent>
          </div>
        </Card>
        <Card density="compact">
          <CardHeader>
            <CardTitle>Go / No-Go</CardTitle>
            <CardDescription>Tenant-wide pre-flight across the governed queue. Per-request gates are on each request page.</CardDescription>
          </CardHeader>
          {executionTenantMissing ? (
            <CardContent>
              <p className="muted">Select an execution tenant to compute pre-flight gates.</p>
            </CardContent>
          ) : (
            <CardContent className="stack-tight">
              <p role="status"><Badge tone={goNoGoVerdict.tone}>{goNoGoVerdict.label}</Badge></p>
              <div className="kv-list">
                {goNoGoGates.map((gate) => (
                  <KvField key={gate.key} label={gate.label}>
                    <Badge tone={gate.tone}>{gate.status}</Badge>
                  </KvField>
                ))}
              </div>
              <p className="muted text-xs">Running tests and open findings are informational and do not change the verdict.</p>
            </CardContent>
          )}
        </Card>
      </div>
    </>
  );

  return (
    <div className="content">
      <PageHeader
        route="internal-soc"
        context={staffSocSurface ? 'Privileged staff plane' : 'SOC role'}
        description="Governed request review, authorization custody, provider coordination, bounded execution limits, and tenant emergency stop controls."
      />
      {staffSocSurface ? (
        <Card>
          <CardHeader>
            <CardTitle>Execution tenant</CardTitle>
            <CardDescription>
              Staff SOC actions are tenant-scoped. Choose a tenant here, or use Work on tenant on a row in Cross-tenant execution.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <Select
              label="Tenant"
              value={effectiveSocTenant}
              options={tenantSelectOptions}
              onChange={(value) => void applyExecutionTenant(value)}
            />
            {!effectiveSocTenant ? (
              <p className="muted mt-3" role="status">
                No execution tenant selected — queue hydration and all tenant mutations stay disabled until you choose one.
              </p>
            ) : null}
            {suggestedExecutionTenant ? (
              <div className="mt-3">
                <Button
                  size="sm"
                  variant="secondary"
                  loading={queueRefreshing}
                  onClick={() => void applyExecutionTenant(suggestedExecutionTenant)}
                >
                  Work on {tenantDisplayName(suggestedExecutionTenant)}
                </Button>
                <p className="muted small mt-3">Only one tenant has governed high-scale work in the cross-tenant queue.</p>
              </div>
            ) : null}
          </CardContent>
        </Card>
      ) : null}
      {staffSocSurface ? controls : null}
      {executionTenantMissing ? (
        <div className="callout">
          <Info size={18} aria-hidden="true" />
          <span>Select an execution tenant to read its kill-switch state.</span>
        </div>
      ) : (
        <div className={killSwitchActive ? 'callout warn' : 'callout info'}>
          {killSwitchActive ? <Siren size={18} aria-hidden="true" /> : <ShieldCheck size={18} aria-hidden="true" />}
          <span>
            {killSwitchActive
              ? 'Kill switch is active — new safe runs are blocked, active safe runs are cancelled, and governed high-scale execution is stopped for this tenant.'
              : 'Kill switch is clear. Safe checks remain bounded; high-scale execution still requires accepted authorization, provider approval when required, and an approved schedule.'}
          </span>
        </div>
      )}
      <div className="kpi-row" role="group" aria-label="SOC console summary">
        {staffSocSurface ? (
          <KpiCell label="Active tenants" value={formatNumber(activeTenantCount)} delta="with governed requests" />
        ) : (
          <KpiCell label="Queue" value={formatNumber(data.highScale.length)} delta="governed requests" />
        )}
        <KpiCell label="Scheduled" value={executionTenantMissing ? '—' : formatNumber(scheduledCount)} delta={executionTenantMissing ? 'Select a tenant' : 'approved or scheduled'} />
        <KpiCell label="In review" value={executionTenantMissing ? '—' : formatNumber(inReviewCount)} delta={executionTenantMissing ? 'Select a tenant' : 'awaiting SOC decision'} tone={!executionTenantMissing && inReviewCount > 0 ? 'warn' : 'muted'} />
        {executionTenantMissing ? (
          <KpiCell label="Kill switch" value="—" delta="Select a tenant" tone="muted" />
        ) : (
          <KpiCell label="Kill switch" value={killSwitchActive ? 'Active' : 'Clear'} delta="tenant emergency stop" tone={killSwitchActive ? 'danger' : 'success'} />
        )}
      </div>
      <PageContextSummary>
        {staffSocSurface ? (
          <>
            Cross-tenant <span className="tabular-nums">{formatNumber(crossTenantRequestCount)}</span> governed {pluralize(crossTenantRequestCount, 'request')} across{' '}
            <span className="tabular-nums">{formatNumber(activeTenantCount)}</span> {pluralize(activeTenantCount, 'tenant')}
            {executionTenantMissing ? null : ' · '}
          </>
        ) : null}
        {executionTenantMissing ? null : (
          <>
            Queue <span className="tabular-nums">{formatNumber(data.highScale.length)}</span> governed {pluralize(data.highScale.length, 'request')} ·{' '}
            <span className="tabular-nums">{formatNumber(openFindingsCount)}</span> open {pluralize(openFindingsCount, 'finding')}
          </>
        )}
      </PageContextSummary>
      {staffSocSurface ? null : controls}
      {staffSocSurface ? (
        <Card>
          <CardHeader>
            <CardTitle>Cross-tenant execution</CardTitle>
            <CardDescription>Governed high-scale requests across all customer tenants, read from the audited staff SOC queue. Running requests are listed first. Open a request for the full lifecycle workspace.</CardDescription>
          </CardHeader>
          <CardContent>
            <DataTable
              columns={socCrossTenantColumns}
              items={crossTenantHighScale}
              getRowId={(item) => `${item.tenantId}:${item.id}`}
              loadError={socQueue.error}
              onRetry={() => void refreshSocConsole()}
              empty={<EmptyState icon={Users} title="No cross-tenant high-scale requests." body="Governed requests across tenants appear here after intake and authorization-pack review." />}
            />
          </CardContent>
        </Card>
      ) : null}
      <Card>
        <CardHeader>
          <CardTitle>High-scale queue</CardTitle>
          <CardDescription>{staffSocSurface
            ? 'Governed requests for the active execution-tenant context. Open a request for the full lifecycle workspace; quick approve is offered for submitted or in-review requests once the authorization pack is accepted.'
            : 'Open a request for the full lifecycle workspace. Quick approve is offered for submitted or in-review requests once the authorization pack is accepted.'}</CardDescription>
        </CardHeader>
        <CardContent aria-busy={queueRefreshing}>
          <DataTable
            columns={requestColumns}
            items={data.highScale}
            loadError={data.loadErrors.highScale}
            onRetry={() => void onRefresh()}
            empty={queueRefreshing ? (
              <TableQueueSkeleton />
            ) : (
              executionTenantMissing
                ? <EmptyState icon={ShieldCheck} title="Select a tenant to load its queue." body="The high-scale queue for a tenant loads after you choose one above." />
                : <EmptyState icon={ShieldCheck} title="No high-scale requests." body="Customer requests appear here after intake and authorization-pack review." />
            )}
          />
        </CardContent>
      </Card>
      <div className="split">
        <Card>
          <CardHeader>
            <CardTitle>Execution timeline</CardTitle>
            <CardDescription>Recorded lifecycle events across governed requests, ordered chronologically.</CardDescription>
          </CardHeader>
          <CardContent>
            {executionTimeline.length === 0 ? (
              executionTenantMissing
                ? <EmptyState icon={Activity} title="Select a tenant to load its timeline." body="Execution events for a tenant load after you choose one above." />
                : <EmptyState icon={Activity} title="No execution timeline yet." body="Lifecycle events appear after SOC approval, scheduling, or execution actions." />
            ) : (
              <div className="timeline-list">
                {executionTimeline.map((event, index) => (
                  <div key={event.key}>
                    <span>{index + 1}</span>
                    <div>
                      <strong>{formatGovernanceStatusLabel(event.action)} · <span title={event.requestId}>{event.objective || 'High-scale request'}</span></strong>
                      <p>{formatDate(event.at)} · {event.by}</p>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>Provider contacts</CardTitle>
            <CardDescription>Provider and emergency contacts declared on governed high-scale requests.</CardDescription>
          </CardHeader>
          <CardContent>
            <DataTable
              columns={providerContactColumns}
              items={providerContactRows}
              getRowId={(item) => item.id}
              empty={executionTenantMissing
                ? <EmptyState icon={Users} title="Select a tenant to load its contacts." body="Provider contacts for a tenant load after you choose one above." />
                : <EmptyState icon={Users} title="No provider or emergency contacts." body="Contacts appear after authorization-pack intake declares provider and emergency contacts." />}
            />
          </CardContent>
        </Card>
      </div>
      {output ? (
        <Card>
          <CardHeader>
            <CardTitle>
              {lastActionRequestId
                ? <>Action output — <code className="traffic-path-label" title={lastActionRequestId}>{lastActionRequestId}</code></>
                : 'Action output — tenant controls'}
            </CardTitle>
            {lastActionRequestId ? (
              <CardDescription>
                <AnchorButton size="sm" variant="ghost" href={buildDetailHref('queue-detail', lastActionRequestId)}>Open request detail</AnchorButton>
              </CardDescription>
            ) : null}
          </CardHeader>
          <CardContent>
            <div className="callout info" role="status" aria-live="polite">
              <CheckCircle2 size={18} aria-hidden="true" />
              <span>{outputSummary || 'Action completed successfully.'}</span>
            </div>
            <Button
              size="sm"
              variant="ghost"
              aria-expanded={showActionTechnicalDetails}
              aria-controls="soc-action-technical-output"
              onClick={() => setShowActionTechnicalDetails((open) => !open)}
            >
              {showActionTechnicalDetails ? 'Hide technical details' : 'View technical details'}
            </Button>
            {showActionTechnicalDetails ? (
              <pre
                className="codeblock"
                id="soc-action-technical-output"
                tabIndex={0}
                role="region"
                aria-label="SOC action technical output, scrollable"
              >{output}</pre>
            ) : null}
          </CardContent>
        </Card>
      ) : null}
    </div>
  );
}
