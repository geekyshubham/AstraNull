import { useEffect, useMemo, useRef, useState, type FormEvent, type ReactNode } from 'react';
import { Activity, Bell, CalendarClock, CheckCircle2, ClipboardList, Copy, FileText, Info, Lock, Search, ShieldCheck, Siren, Users } from 'lucide-react';
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
  GOVERNED_HIGH_SCALE_SCENARIOS,
  buildLifecycleTimeline,
  providerApprovalRequired
} from '../lib/high-scale';
import { isFindingOpen } from '../lib/finding-lifecycle.mjs';
import type { DataItem, PortalConfig, PortalData, Session } from '../lib/types';
import { buildDetailHref, getRouteTenantId, parseInspectorRef, replaceRouteParams } from '../lib/route-params';
import { apiErrorMessage } from '../lib/error-messages';
import { formatAuditAction, formatDate, formatNumber, sensitiveResourceLabel } from '../lib/utils';
// @ts-ignore Plain ESM keeps machine-code labels directly testable with node:test.
import { plainCodeLabel } from '../lib/plain-language.mjs';
import { CustomerPageStyles, MetricCard, PageContextSummary, PageHeader, PanelCardHeader } from './page-components';
import { useConfirmModal } from '../lib/crud-ui';
import { PortalLoadingSkeleton } from '../lib/empty-from-api';

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

const NOTIFICATION_TRIGGERS = [
  'finding.high_severity',
  'safe_test.completed',
  'high_scale.state_change',
  'report.ready'
] as const;

const NOTIFICATION_TRIGGER_LABELS: Record<(typeof NOTIFICATION_TRIGGERS)[number], string> = {
  'finding.high_severity': 'High-severity finding',
  'safe_test.completed': 'Safe test completed',
  'high_scale.state_change': 'High-scale state change',
  'report.ready': 'Report ready'
};

function humanizeNotificationTrigger(trigger: string) {
  const known = NOTIFICATION_TRIGGER_LABELS[trigger as (typeof NOTIFICATION_TRIGGERS)[number]];
  if (known) return known;
  return trigger
    .split('.')
    .map((segment) => segment.split('_').map((word) => word.charAt(0).toUpperCase() + word.slice(1)).join(' '))
    .join(' · ');
}

function isFlatMetadataObject(value: unknown): value is Record<string, string | number | boolean | null> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  return Object.values(value).every(
    (entry) => entry === null || ['string', 'number', 'boolean'].includes(typeof entry)
  );
}

function targetGroupDisplayName(data: PortalData, groupId: string) {
  const group = data.targetGroups.find((item) => getString(item, ['id'], '') === groupId);
  return getString(group ?? {}, ['name', 'title'], groupId || '—');
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

function validateNotificationDestination(channel: string, rawDestination: string): { destination: string } | { error: string } {
  const destination = rawDestination.trim();
  if (channel === 'in_app') {
    return { destination: '' };
  }
  if (channel === 'webhook') {
    if (!/^https?:\/\/.+/i.test(destination)) {
      return { error: 'Enter a valid http(s) webhook URL before adding the rule.' };
    }
    try {
      const parsed = new URL(destination);
      if (!['http:', 'https:'].includes(parsed.protocol)) {
        return { error: 'Webhook destination must use http or https.' };
      }
    } catch {
      return { error: 'Enter a valid webhook URL before adding the rule.' };
    }
    return { destination };
  }
  if (channel === 'email') {
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(destination)) {
      return { error: 'Enter a valid email address before adding the rule.' };
    }
    return { destination };
  }
  if (!destination) {
    return { error: 'Enter a destination before adding the rule.' };
  }
  return { destination };
}

function summarizeSocActionPayload(payload: unknown) {
  if (!payload || typeof payload !== 'object') return 'Action completed successfully.';
  const item = payload as DataItem;
  if ('active' in item) {
    return item.active ? 'Kill switch is now active for this tenant.' : 'Kill switch cleared; governed runs may resume when approved.';
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

function highScaleStateBadgeTone(state: string): GovernanceBadgeTone {
  const normalized = state.trim().toLowerCase();
  if (['closed', 'completed', 'cancelled', 'canceled'].includes(normalized)) return 'success';
  if (['running', 'executing', 'active', 'started'].includes(normalized)) return 'danger';
  if (['scheduled', 'approved'].includes(normalized)) return 'info';
  if (['submitted', 'under_review', 'pending', 'draft'].includes(normalized)) return 'warn';
  return 'muted';
}

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
  return 'info';
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
  return trimmed.replace(/_/g, ' ');
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

function governedLimitDisplay(item: DataItem) {
  const familyId = Array.isArray(item.requested_scenario_families)
    ? String(item.requested_scenario_families[0] ?? '')
    : '';
  const scenario = GOVERNED_HIGH_SCALE_SCENARIOS.find((entry) => entry.id === familyId);
  const limits = item.requested_limits && typeof item.requested_limits === 'object' && !Array.isArray(item.requested_limits)
    ? item.requested_limits as DataItem
    : {};
  const rateValue = scenario ? limits[scenario.limit.field] : undefined;
  const rate = scenario && typeof rateValue === 'number'
    ? `${formatNumber(rateValue)} ${scenario.limit.unit}`
    : '';
  const durationValue = limits.max_duration_minutes;
  const duration = typeof durationValue === 'number'
    ? `${formatNumber(durationValue)} min`
    : '';
  return [rate, duration].filter(Boolean).join(' · ') || '—';
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

const NOTIFICATION_CHANNEL_OPTIONS = [
  { value: 'webhook', label: 'Webhook' },
  { value: 'email', label: 'Email' },
  { value: 'slack', label: 'Slack' },
  { value: 'teams', label: 'Teams' },
  { value: 'in_app', label: 'In-app' }
] as const;

function deliveryAttempts(events: DataItem[]) {
  return events.flatMap((event) => {
    const attempts = Array.isArray(event.delivery_attempts) ? event.delivery_attempts as DataItem[] : [];
    return attempts.map((attempt) => ({
      ...attempt,
      event_id: event.id,
      trigger: event.trigger
    }));
  });
}

type ProviderHealthRow = {
  channel: string;
  label: string;
  detail: string;
  ruleCount: number;
  enabledCount: number;
  delivered: number;
  retrying: number;
  dlq: number;
  tone: GovernanceBadgeTone;
  status: string;
};

// Derives per-provider delivery health from real notification rules (configured channels)
// correlated with recorded delivery attempts. No provider status is hardcoded.
function buildProviderHealthRows(rules: DataItem[], attempts: DataItem[]): ProviderHealthRow[] {
  type Acc = { ruleCount: number; enabledCount: number; delivered: number; retrying: number; dlq: number; detail: string };
  const channels = new Map<string, Acc>();
  const ensure = (channel: string): Acc => {
    const existing = channels.get(channel);
    if (existing) return existing;
    const created: Acc = { ruleCount: 0, enabledCount: 0, delivered: 0, retrying: 0, dlq: 0, detail: '' };
    channels.set(channel, created);
    return created;
  };
  for (const rule of rules) {
    const channel = getString(rule, ['channel'], '').trim();
    if (!channel || channel === '—') continue;
    const entry = ensure(channel);
    entry.ruleCount += 1;
    if (rule.enabled !== false) entry.enabledCount += 1;
    if (!entry.detail) {
      const dest = getString(rule, ['destination_preview'], '');
      if (dest && dest !== '—') entry.detail = dest;
    }
  }
  for (const attempt of attempts) {
    const channel = getString(attempt, ['channel'], '').trim();
    if (!channel || channel === '—') continue;
    const entry = ensure(channel);
    const status = getString(attempt, ['status'], '');
    if (status === 'delivered_provider') entry.delivered += 1;
    else if (status === 'provider_retry_scheduled') entry.retrying += 1;
    else if (status === 'provider_failed_dlq') entry.dlq += 1;
    if (!entry.detail) {
      const dest = getString(attempt, ['destination_preview'], '');
      if (dest && dest !== '—') entry.detail = dest;
    }
  }
  return Array.from(channels.entries())
    .map(([channel, entry]) => {
      const label = NOTIFICATION_CHANNEL_OPTIONS.find((option) => option.value === channel)?.label
        ?? formatGovernanceStatusLabel(channel);
      let tone: GovernanceBadgeTone;
      let status: string;
      if (entry.dlq > 0) {
        tone = 'danger';
        status = 'Dead-letter';
      } else if (entry.retrying > 0) {
        tone = 'warn';
        status = 'Retrying';
      } else if (entry.delivered > 0) {
        tone = 'success';
        status = 'Healthy';
      } else {
        tone = 'muted';
        status = entry.ruleCount > 0 ? 'Idle' : 'No rules';
      }
      const detail = entry.detail
        || (entry.ruleCount > 0 ? `${entry.ruleCount} rule${entry.ruleCount === 1 ? '' : 's'}` : 'metadata-only');
      return { channel, label, ...entry, detail, tone, status };
    })
    .sort((left, right) => left.label.localeCompare(right.label));
}

function GovernanceFeedbackBanner({ message, error }: { message: string; error: string }) {
  if (!message && !error) return null;
  return (
    <div
      className={error ? 'form-banner error' : 'form-banner'}
      role={error ? 'alert' : 'status'}
      aria-live="polite"
    >
      {error || message}
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
  children
}: {
  titleId: string;
  title: string;
  description: string;
  children: ReactNode;
}) {
  return (
    <section className="operation-panel" aria-labelledby={titleId}>
      <div>
        <h3 id={titleId}>{title}</h3>
        <p>{description}</p>
      </div>
      <div className="row-actions">{children}</div>
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
          <Badge tone={active ? 'danger' : 'success'}>{active ? 'Active' : 'Inactive'}</Badge>
        </KvField>
        <KvField label="Reason">{reason}</KvField>
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

// Validated kill-switch sequence, mirroring the frozen server contract
// (src/contracts/killSwitchValidation.mjs → KILL_SWITCH_REQUIRED_STEP_IDS).
// Rendered as the documented arming sequence; each step is custody-recorded on exercise.
const KILL_SWITCH_VALIDATED_SEQUENCE = [
  'activate_tenant_kill_switch',
  'block_new_safe_runs',
  'cancel_active_safe_runs',
  'probe_fleet_stops_leasing',
  'adapter_stop_path_invoked',
  'audit_timeline_recorded',
  'clear_and_resume_guarded'
] as const;

function normalizeHighScaleState(item: DataItem) {
  return getString(item, ['state'], '').trim().toLowerCase();
}

type SocGoNoGoGate = { key: string; label: string; tone: GovernanceBadgeTone; status: string };

function socPackGate(actionableCount: number, pendingCount: number): { tone: GovernanceBadgeTone; status: string } {
  if (actionableCount === 0) return { tone: 'muted', status: 'No open requests' };
  if (pendingCount === 0) return { tone: 'success', status: 'All accepted' };
  return { tone: 'warn', status: `${formatNumber(pendingCount)} pending` };
}

function buildSocGoNoGoGates(
  requests: DataItem[],
  context: { killSwitchActive: boolean; runningCount: number; openFindings: number }
): SocGoNoGoGate[] {
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
    { key: 'packs', label: 'Authorization packs reviewed', ...socPackGate(actionable.length, actionable.length - packAccepted) },
    {
      key: 'providers',
      label: 'Provider approvals',
      tone: providerRequired.length === 0 ? 'muted' : providerAccepted === providerRequired.length ? 'success' : 'warn',
      status: providerRequired.length === 0
        ? 'Not required'
        : providerAccepted === providerRequired.length
          ? 'All accepted'
          : `${formatNumber(providerRequired.length - providerAccepted)} pending`
    },
    {
      key: 'kill',
      label: 'Kill switch clear',
      tone: context.killSwitchActive ? 'danger' : 'success',
      status: context.killSwitchActive ? 'Armed' : 'Clear'
    },
    {
      key: 'execution',
      label: 'Managed execution only',
      tone: context.runningCount > 0 ? 'info' : 'success',
      status: context.runningCount > 0 ? `${context.runningCount} active` : 'Idle'
    },
    {
      key: 'findings',
      label: 'Findings triaged',
      tone: context.openFindings > 0 ? 'warn' : 'success',
      status: context.openFindings > 0 ? `${context.openFindings} open` : 'Clear'
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
    render: (item) => (item.provider === '—' ? <span className="muted">—</span> : <Badge tone="info">{item.provider}</Badge>)
  },
  { key: 'contact', label: 'Contact', render: (item) => <span className="mono">{item.contact}</span> },
  {
    key: 'role',
    label: 'Role',
    render: (item) => (item.role === '—' ? <span className="muted">—</span> : formatGovernanceStatusLabel(item.role))
  }
];

type SocTimelineRow = { key: string; requestId: string; action: string; at: string; by: string };

function buildSocExecutionTimeline(requests: DataItem[]): SocTimelineRow[] {
  return requests
    .flatMap((request) => {
      const requestId = getString(request, ['id'], '—');
      return buildLifecycleTimeline(request).map((event, index) => ({
        key: `${requestId}::${index}::${event.at}`,
        requestId,
        action: event.action,
        at: event.at,
        by: event.by
      }));
    })
    .sort((left, right) => new Date(left.at).getTime() - new Date(right.at).getTime())
    .slice(-12);
}

type SocCrossTenantRow = { id: string; tenantId: string; kind: string; state: string; requestedAt: string };

// Staff SOC surface only: rows come from GET /internal/admin/soc/high-scale-requests (staff:soc:read, audited).
function isHighScaleApprovalKind(kind: string) {
  return kind.trim().toLowerCase().startsWith('high_scale');
}

function buildSocCrossTenantRows(approvals: DataItem[]): SocCrossTenantRow[] {
  return approvals
    .filter((item) => isHighScaleApprovalKind(getString(item, ['kind'], '')))
    .map((item) => ({
      // Prefer linked high-scale request id over the internal approval record id.
      id: getString(item, ['high_scale_request_id', 'subject_id', 'resource_id', 'request_id', 'id'], '—'),
      tenantId: getString(item, ['tenant_id'], '—'),
      kind: getString(item, ['kind'], '—'),
      state: getString(item, ['state'], '—'),
      requestedAt: getString(item, ['created_at', 'requested_at'], '')
    }))
    .sort((left, right) => new Date(right.requestedAt).getTime() - new Date(left.requestedAt).getTime());
}

const socCrossTenantColumns: TableColumn<SocCrossTenantRow>[] = [
  { key: 'tenant', label: 'Tenant', render: (item) => <span className="mono">{item.tenantId}</span> },
  { key: 'request', label: 'Request', render: (item) => <span title={item.id}>High-scale request</span> },
  { key: 'kind', label: 'Kind', render: (item) => <Badge tone="info">{formatGovernanceStatusLabel(item.kind, 'high scale')}</Badge> },
  {
    key: 'state',
    label: 'State',
    render: (item) => <Badge tone={highScaleStateBadgeTone(item.state)}>{formatGovernanceStatusLabel(item.state, 'Unknown')}</Badge>
  },
  { key: 'requested', label: 'Requested', render: (item) => formatDate(item.requestedAt) },
  {
    key: 'actions',
    label: 'Actions',
    render: (item) => (
      <AnchorButton
        size="sm"
        variant="secondary"
        href={buildDetailHref('queue-detail', item.id, {
          tenantId: item.tenantId !== '—' ? item.tenantId : undefined
        })}
      >
        Open
      </AnchorButton>
    )
  }
];

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
  const [destinationError, setDestinationError] = useState('');
  const [triggerError, setTriggerError] = useState('');
  const [ruleFormOpen, setRuleFormOpen] = useState(false);
  const [ruleMode, setRuleMode] = useState<'new' | 'existing'>('new');
  const [existingRuleId, setExistingRuleId] = useState('');
  const [ruleChannel, setRuleChannel] = useState('webhook');
  const [ruleTriggers, setRuleTriggers] = useState<string[]>(['finding.high_severity']);
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

  async function handleCreateRule(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const formEl = event.currentTarget;
    const triggers = NOTIFICATION_TRIGGERS.filter((trigger) => ruleTriggers.includes(trigger));
    if (triggers.length === 0) {
      setTriggerError('Choose at least one event to route.');
      return;
    }
    setTriggerError('');
    if (ruleMode === 'existing') {
      const rule = rules.find((item) => getString(item, ['id'], '') === existingRuleId);
      if (!rule) {
        setDestinationError('Choose an existing channel.');
        return;
      }
      setDestinationError('');
      const merged = [...new Set([...(Array.isArray(rule.triggers) ? (rule.triggers as unknown[]).map(String) : []), ...triggers])];
      const updated = await runAction('create-notification-rule', () => requestJson(config, session, `/v1/notifications/${encodeURIComponent(existingRuleId)}`, {
        method: 'PATCH',
        body: { triggers: merged, enabled: ruleEnabled }
      }), `Routed ${triggers.map(humanizeNotificationTrigger).join(', ')} to the existing ${getString(rule, ['channel'])} channel ${getString(rule, ['destination_preview'], '')}. Its stored destination was not changed.`);
      if (updated) setRuleFormOpen(false);
      return;
    }
    const form = new FormData(formEl);
    const channel = ruleChannel.trim();
    const validation = validateNotificationDestination(channel, String(form.get('destination_preview') ?? ''));
    if ('error' in validation) {
      setDestinationError(validation.error);
      return;
    }
    setDestinationError('');
    const created = await runAction('create-notification-rule', () => requestJson(config, session, '/v1/notifications', {
      method: 'POST',
      body: { channel, enabled: ruleEnabled, triggers, destination: validation.destination }
    }), `Rule created ${ruleEnabled ? 'and enabled' : 'disabled'}. Nothing was sent; the first message goes out when a matching event occurs and outbound delivery is enabled.`);
    if (created) {
      formEl.reset();
      setRuleFormOpen(false);
    }
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
            <span>{NOTIFICATION_CHANNEL_OPTIONS.find((option) => option.value === channel)?.label ?? formatGovernanceStatusLabel(channel)}</span>
            <span className="muted small mono">{getString(item, ['destination_preview'], 'Destination hidden')}</span>
          </span>
        );
      }
    },
    { key: 'triggers', label: 'Routes', render: (item) => (Array.isArray(item.triggers) ? (item.triggers as unknown[]).map((trigger) => humanizeNotificationTrigger(String(trigger))).join(', ') : '') || <span className="muted">No events</span> },
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
    { key: 'event', label: 'Event', render: (view) => <span className="cp-stack"><span>{humanizeNotificationTrigger(getString(view.event, ['trigger']))}</span><span className="muted small">{getString(view.event, ['subject'], '')}</span></span> },
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
        description={<>Routing rules decide which events go to which channel. Channel destinations are set up in <a className="cp-link" href="#integrations">Integrations</a>. An event being recorded is not a message delivered.</>}
        actions={canWrite ? (
          <Button
            size="sm"
            variant={ruleFormOpen ? 'ghost' : 'default'}
            aria-expanded={ruleFormOpen}
            aria-controls={ruleFormOpen ? 'notifications-create-rule' : undefined}
            onClick={() => setRuleFormOpen((open) => !open)}
          >
            {ruleFormOpen ? 'Close routing form' : 'Route events'}
          </Button>
        ) : <Badge tone="muted">Read only</Badge>}
      />
      <dl className="release-dimensions" aria-label="Delivery summary for loaded events">
        <div><dt>Channels</dt><dd>{formatNumber(enabledRules)} of {formatNumber(rules.length)}</dd><dd className="release-dimension-hint">enabled</dd></div>
        <div><dt>Delivered</dt><dd>{eventsUnavailable ? '—' : formatNumber(counts.delivered)}</dd><dd className="release-dimension-hint">attempts accepted by a provider or in-app</dd></div>
        <div><dt>Failed or retrying</dt><dd>{eventsUnavailable ? '—' : formatNumber(counts.failed + counts.retry)}</dd><dd className="release-dimension-hint">{formatNumber(counts.failed)} failed · {formatNumber(counts.retry)} retry scheduled</dd></div>
        <div><dt>Recorded, not sent</dt><dd>{eventsUnavailable ? '—' : formatNumber(counts.notSent)}</dd><dd className="release-dimension-hint">outbound delivery disabled{counts.unknown ? ` · ${formatNumber(counts.unknown)} unknown` : ''}</dd></div>
      </dl>
      <p className="muted small">Counts cover the {formatNumber(events.length)} most recent events loaded, not all history.</p>
      <GovernanceFeedbackBanner message={message} error={error} />

      {canWrite && ruleFormOpen ? (
        <Card id="notifications-create-rule" raised>
          <CardHeader>
            <div>
              <CardTitle><span ref={formHeadingRef} tabIndex={-1}>Route events to a channel</span></CardTitle>
              <CardDescription>Send chosen events to a new destination, or add them to a channel you already set up. Saving sends nothing.</CardDescription>
            </div>
          </CardHeader>
          <CardContent>
            <form className="product-form" onSubmit={handleCreateRule} aria-busy={busy === 'create-notification-rule'} noValidate>
              <fieldset className="full report-kind-group">
                <legend>Destination</legend>
                <div className="cp-toolbar">
                  <label className="check-row"><input type="radio" name="rule_mode" checked={ruleMode === 'new'} onChange={() => { setRuleMode('new'); setDestinationError(''); }} /><span>New destination</span></label>
                  <label className="check-row"><input type="radio" name="rule_mode" checked={ruleMode === 'existing'} disabled={rules.length === 0} onChange={() => { setRuleMode('existing'); setDestinationError(''); }} /><span>Existing channel{rules.length === 0 ? ' (none yet)' : ''}</span></label>
                </div>
              </fieldset>
              {ruleMode === 'new' ? (
                <>
                  <Select
                    label="Channel type"
                    value={ruleChannel}
                    options={NOTIFICATION_CHANNEL_OPTIONS.map((option) => ({ value: option.value, label: option.label }))}
                    onChange={(value) => { setRuleChannel(value); setDestinationError(''); }}
                    disabled={busy !== ''}
                  />
                  <label className="full">
                    <span>{ruleChannel === 'in_app' ? 'Destination (not needed for in-app)' : 'Destination'}</span>
                    <input
                      name="destination_preview"
                      placeholder={ruleChannel === 'email' ? 'alerts@example.com' : ruleChannel === 'in_app' ? 'Delivered to the in-app feed' : 'https://hooks.example.invalid/notifications'}
                      autoComplete="off"
                      spellCheck={false}
                      aria-invalid={destinationError ? true : undefined}
                      aria-describedby={destinationError ? 'notification-destination-error' : 'notification-destination-help'}
                      disabled={busy !== '' || ruleChannel === 'in_app'}
                    />
                    <span className="muted small" id="notification-destination-help">Webhook URLs can contain secrets. After saving, only a redacted preview is shown and the URL is not kept in this form.</span>
                  </label>
                </>
              ) : (
                <Select
                  className="full"
                  label="Existing channel"
                  value={existingRuleId}
                  options={[{ value: '', label: 'Choose a channel' }, ...rules.map((rule) => ({
                    value: getString(rule, ['id'], ''),
                    label: `${NOTIFICATION_CHANNEL_OPTIONS.find((option) => option.value === getString(rule, ['channel']))?.label ?? getString(rule, ['channel'])} · ${getString(rule, ['destination_preview'], 'destination hidden')}`
                  }))]}
                  onChange={(value) => { setExistingRuleId(value); setDestinationError(''); }}
                  error={destinationError || undefined}
                />
              )}
              <fieldset className="full">
                <legend>Events to route</legend>
                {NOTIFICATION_TRIGGERS.filter((trigger) => trigger !== 'high_scale.state_change').map((trigger) => (
                  <label key={trigger} className="check-row">
                    <input type="checkbox" name="triggers" value={trigger} checked={ruleTriggers.includes(trigger)} onChange={() => toggleRuleTrigger(trigger)} disabled={busy !== ''} />
                    <span>{humanizeNotificationTrigger(trigger)}</span>
                  </label>
                ))}
              </fieldset>
              {triggerError ? <p className="field-error full" role="alert">{triggerError}</p> : null}
              <label className="check-row full">
                <input type="checkbox" name="enabled" checked={ruleEnabled} onChange={(changeEvent) => setRuleEnabled(changeEvent.target.checked)} disabled={busy !== ''} />
                <span>Enabled after saving</span>
              </label>
              {destinationError && ruleMode === 'new' ? <p className="field-error full" id="notification-destination-error" role="alert">{destinationError}</p> : null}
              <div className="form-actions full">
                <Button type="button" variant="ghost" disabled={busy !== ''} onClick={() => setRuleFormOpen(false)}>Cancel</Button>
                <Button type="submit" loading={busy === 'create-notification-rule'} disabled={busy !== '' && busy !== 'create-notification-rule'}>{ruleMode === 'existing' ? 'Add to channel' : 'Save rule'}</Button>
              </div>
              <p className="muted small full">Your channel type, events, and enabled choice are kept if you close this form; the destination is not.</p>
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
                'aria-label': `Inspect ${attemptStatusCopy(view.status).label.toLowerCase()} delivery for ${humanizeNotificationTrigger(getString(view.event, ['trigger']))}`,
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
                : <EmptyState icon={ClipboardList} title="No delivery attempts recorded." body={rules.length ? 'Attempts appear when a routed event occurs.' : 'Route events to a channel first.'} />}
            />
          </CardContent>
        </Card>
        {selected && selectedCopy ? (
          <Card className="release-record-detail" raised>
            <section aria-label="Selected delivery attempt">
              <CardHeader>
                <div>
                  <CardTitle>{selectedCopy.label}: {humanizeNotificationTrigger(getString(selected.event, ['trigger']))}</CardTitle>
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
                  <KvField label="Rule">{selected.rule ? `${selected.rule.enabled === false ? 'Disabled' : 'Enabled'} · routes ${(Array.isArray(selected.rule.triggers) ? (selected.rule.triggers as unknown[]).length : 0)} event types` : 'Rule removed or not recorded'}</KvField>
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
        <PanelCardHeader title="Routing rules" description="Each rule sends chosen events to one channel. Edit destinations and turn channels on or off in Integrations." />
        <CardContent>
          <DataTable
            columns={ruleColumns}
            items={rules}
            getRowId={(item) => getString(item, ['id'], '')}
            empty={<EmptyState icon={Bell} title="No routing rules." body="Nothing is routed to a channel yet." actionLabel={canWrite ? 'Route events' : undefined} onAction={canWrite ? () => setRuleFormOpen(true) : undefined} />}
            loadError={data.loadErrors.notificationRules}
            onRetry={() => void onRefresh()}
          />
        </CardContent>
      </Card>

      {canWrite ? (
        <Card>
          <PanelCardHeader title="Bulk recovery" description="Preview first. Live actions apply to every matching attempt and can produce duplicates if earlier sends arrived." />
          <CardContent className="stack-tight">
            <DeliveryOperationPanel titleId="notification-retries-title" title="Due retries" description={batchPreview?.kind === 'retries' ? `Preview: ${batchPreview.summary}` : 'Process retries whose scheduled time has passed.'}>
              <Button size="sm" variant="secondary" loading={busy === 'batch-preview-retries'} disabled={busy !== ''} onClick={() => void previewBatch('retries')}>Preview due retries</Button>
              <Button size="sm" variant="secondary" loading={busy === 'batch-retries'} disabled={busy !== '' || batchPreview?.kind !== 'retries'} onClick={() => void runBatch('retries')}>Process due retries</Button>
            </DeliveryOperationPanel>
            <DeliveryOperationPanel titleId="notification-failed-title" title="Failed deliveries" description={batchPreview?.kind === 'failed' ? `Preview: ${batchPreview.summary}` : `${formatNumber(counts.failed)} failed attempt${counts.failed === 1 ? '' : 's'} on this page.`}>
              <Button size="sm" variant="secondary" loading={busy === 'batch-preview-failed'} disabled={busy !== '' || counts.failed === 0} onClick={() => void previewBatch('failed')}>Preview retry of failed</Button>
              <Button size="sm" variant="secondary" loading={busy === 'batch-failed'} disabled={busy !== '' || counts.failed === 0 || batchPreview?.kind !== 'failed'} onClick={() => void runBatch('failed')}>Retry failed deliveries</Button>
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
  target_group: 'target-group-detail',
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

/** Server query for the exact filters the user applied; local calendar days become inclusive instants. */
export function auditListQuery(filters: AuditFilters, cursor: string, limit = AUDIT_PAGE_SIZE) {
  const params = new URLSearchParams();
  if (filters.actor.trim()) params.set('actor', filters.actor.trim());
  if (filters.action.trim()) params.set('action', filters.action.trim());
  if (filters.resource.trim()) params.set('resource', filters.resource.trim());
  const since = auditDayBound(filters.since, false);
  const until = auditDayBound(filters.until, true);
  if (Number.isFinite(since)) params.set('since', new Date(since).toISOString());
  if (Number.isFinite(until)) params.set('until', new Date(until).toISOString());
  if (cursor) params.set('cursor', cursor);
  params.set('limit', String(limit));
  return `/v1/audit-log?${params.toString()}`;
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

  function applyFilters(event?: FormEvent<HTMLFormElement>) {
    event?.preventDefault();
    if (draft.since && draft.until && draft.since > draft.until) {
      setDateError('The start date is after the end date. Fix the range before applying.');
      return;
    }
    setDateError('');
    setApplied({ ...draft, actor: draft.actor.trim(), action: draft.action.trim(), resource: draft.resource.trim() });
    setCursorStack(['']);
  }

  function clearFilters() {
    setDraft(EMPTY_AUDIT_FILTERS);
    setApplied(EMPTY_AUDIT_FILTERS);
    setCursorStack(['']);
    setDateError('');
  }

  const filtersActive = Object.values(applied).some(Boolean);
  const suggestions = (key: 'actor_user_id' | 'action' | 'resource_type') => [...new Set(items.map((entry) => getString(entry, [key], '')).filter((value) => value && value !== '—'))].sort();

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
        <span>{plainCodeLabel(resourceType || 'resource')}</span>
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
    { key: 'action', label: 'Action', render: (item) => <span>{formatAuditAction(getString(item, ['action']))}</span> },
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
  const pageNumber = cursorStack.length;
  const totalText = listState.total === null ? 'total not returned' : `${formatNumber(listState.total)} matching`;

  return (
    <div className="content audit-page">
      <CustomerPageStyles />
      <PageHeader route="audit" title="Audit log" description="Who did what, when, and to which resource. A recorded hash shows what the server stored with each entry. This page does not verify the hash chain. Filters and paging run on the server across the whole log." />
      {!allowed ? (
        <EmptyState icon={Lock} title="Audit access required." body="Owners, admins, SOC, and auditors can read the audit log. Your role cannot, so no events are shown." />
      ) : (
        <>
          <PageContextSummary>
            {listState.status === 'ready' ? <>{totalText}{filtersActive ? ' for the applied filters' : ''} · page {formatNumber(pageNumber)}, newest first</> : listState.status === 'loading' ? 'Loading events…' : 'Events unavailable'}
          </PageContextSummary>
          <form className="audit-filter-toolbar" role="search" aria-label="Audit filters" onSubmit={applyFilters} noValidate>
            <div className="audit-filter-fields">
              <label className="field">
                <span>From ({viewerZone})</span>
                <input type="date" value={draft.since} onChange={(event) => setDraft((current) => ({ ...current, since: event.target.value }))} max={draft.until || undefined} />
              </label>
              <label className="field">
                <span>To ({viewerZone})</span>
                <input type="date" value={draft.until} onChange={(event) => setDraft((current) => ({ ...current, until: event.target.value }))} min={draft.since || undefined} aria-invalid={dateError ? true : undefined} aria-describedby={dateError ? 'audit-date-error' : undefined} />
              </label>
              <label className="field">
                <span>Actor user ID</span>
                <input list="audit-actor-options" value={draft.actor} onChange={(event) => setDraft((current) => ({ ...current, actor: event.target.value }))} placeholder="Exact user ID" autoComplete="off" spellCheck={false} />
                <datalist id="audit-actor-options">{suggestions('actor_user_id').map((value) => <option key={value} value={value} />)}</datalist>
              </label>
              <label className="field">
                <span>Action</span>
                <input list="audit-action-options" value={draft.action} onChange={(event) => setDraft((current) => ({ ...current, action: event.target.value }))} placeholder="Exact action, e.g. report.generated" autoComplete="off" spellCheck={false} />
                <datalist id="audit-action-options">{suggestions('action').map((value) => <option key={value} value={value} />)}</datalist>
              </label>
              <label className="field">
                <span>Resource type or ID</span>
                <input list="audit-resource-options" value={draft.resource} onChange={(event) => setDraft((current) => ({ ...current, resource: event.target.value }))} placeholder="e.g. target or tgt_123" autoComplete="off" spellCheck={false} />
                <datalist id="audit-resource-options">{suggestions('resource_type').map((value) => <option key={value} value={value} />)}</datalist>
              </label>
            </div>
            {dateError ? <p className="field-error" id="audit-date-error" role="alert">{dateError}</p> : null}
            <div className="cp-toolbar">
              <Button type="submit" size="sm">Apply filters</Button>
              {filtersActive ? <Button type="button" size="sm" variant="ghost" onClick={clearFilters}>Clear filters</Button> : null}
              <span className="muted small">Filters match exactly; dates are whole days in your timezone.</span>
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
                    <CardTitle>{formatAuditAction(getString(selectedEntry, ['action']))}</CardTitle>
                    <CardDescription>{auditTimestamp(selectedEntry) ? formatDate(auditTimestamp(selectedEntry)) : 'Time not recorded'} · {plainCodeLabel(getString(selectedEntry, ['resource_type'], 'resource'))}</CardDescription>
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
                      'aria-label': `Inspect ${formatAuditAction(getString(item, ['action'], 'audit event'))} on ${resourceLabel}`
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
                  <span className="muted small">Page {formatNumber(pageNumber)} · {formatNumber(items.length)} events on this page · {totalText}</span>
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
    { key: 'kind', label: 'Required kind', render: (item) => <span title={item.kind}>{plainCodeLabel(item.kind)}</span> },
    { key: 'status', label: 'Inventory', render: () => <Badge tone="warn">No accepted record</Badge> }
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
          <dl className="release-dimensions" aria-label="Release evidence dimensions">
            <div>
              <dt>Inventory</dt>
              <dd>{formatNumber(coverage.recorded)} of {formatNumber(coverage.expected)}</dd>
              <dd className="release-dimension-hint">required kinds have an accepted record · {formatNumber(coverage.missing.length)} missing</dd>
            </div>
            <div>
              <dt>Contract validity</dt>
              <dd>{formatNumber(acceptedValidKinds.size)} of {formatNumber(coverage.expected)}</dd>
              <dd className="release-dimension-hint">{acceptedInvalid.length > 0 ? `${formatNumber(acceptedInvalid.length)} accepted record${acceptedInvalid.length === 1 ? ' fails' : 's fail'} validation` : 'kinds have a contract-valid accepted record'}</dd>
            </div>
            <div>
              <dt>External signoff</dt>
              <dd>{signoff ? formatGovernanceStatusLabel(signoff) : 'Not recorded'}</dd>
              <dd className="release-dimension-hint">Operator attestation{attestation?.checked_at || attestation?.created_at ? ` checked ${formatDate(attestation?.checked_at ?? attestation?.created_at)}` : ', time not recorded'}</dd>
            </div>
            <div>
              <dt>Profile</dt>
              <dd>{getNestedString(attestation, ['profile'], 'Not recorded')}</dd>
              <dd className="release-dimension-hint">Production-ready flag: {productionReadyLabel(attestation?.production_ready)}</dd>
            </div>
          </dl>
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
                  <Button size="sm" variant="ghost" onClick={() => downloadJsonFile(`release-evidence-gap-ledger-${session.tenant_id ?? 'tenant'}.json`, gapLedgerTechnicalPayload())}>Download JSON</Button>
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
  const [output, setOutput] = useState('');
  const [outputSummary, setOutputSummary] = useState('');
  const [showActionTechnicalDetails, setShowActionTechnicalDetails] = useState(false);
  const [lastActionRequestId, setLastActionRequestId] = useState('');
  const [executionTenantId, setExecutionTenantId] = useState(() => getRouteTenantId(session.tenant_id ?? '').trim());

  function setActionOutput(payload: unknown, requestId = '') {
    setOutput(JSON.stringify(payload, null, 2));
    setOutputSummary(summarizeSocActionPayload(payload));
    setShowActionTechnicalDetails(false);
    setLastActionRequestId(requestId);
  }
  const isSoc = staffSocSurface
    ? session.principal === 'staff' && isStaffSocRole(session)
    : session.role === 'soc' && session.principal !== 'staff';
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
    setExecutionTenantId(nextTenant);
    if (!staffSocSurface) return;
    const nextSession = { ...session, tenant_id: nextTenant || undefined };
    saveSession(nextSession);
    setError('');
    setMessage(nextTenant ? `Execution tenant set to ${nextTenant}.` : 'Execution tenant cleared.');
    setQueueRefreshing(true);
    try {
      await onRefresh();
    } finally {
      setQueueRefreshing(false);
    }
  }

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
  const requestColumns: TableColumn<DataItem>[] = [
    { key: 'id', label: 'Request', render: (item) => { const id = getString(item, ['id'], ''); return <span title={id || undefined}>{getString(item, ['objective', 'reason', 'name'], 'High-scale validation request')}</span>; } },
    {
      key: 'state',
      label: 'State',
      render: (item) => {
        const state = getString(item, ['state']);
        return <Badge tone={highScaleStateBadgeTone(state)}>{formatGovernanceStatusLabel(state, 'Unknown')}</Badge>;
      }
    },
    { key: 'target', label: 'Target group', render: (item) => targetGroupDisplayName(data, getString(item, ['target_group_id'])) },
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
        const packReady = getNestedString(item, ['authorization_pack_status', 'overall'], '').toLowerCase() === 'accepted';
        const executionTenantMissing = staffSocSurface && !effectiveSocTenant;
        const approvalDisabledReason = executionTenantMissing
          ? 'Select an execution tenant before approving this request.'
          : !['submitted', 'under_review'].includes(state)
            ? 'Quick approval is available only while a request is submitted or under review.'
            : !packReady
              ? 'Every required authorization artifact and provider approval must be accepted first.'
              : '';
        const approvalControlId = `quick-approve-reason-${id}`;
        return (
          <div className="stack-tight">
            <AnchorButton
              size="sm"
              variant="secondary"
              href={buildDetailHref('queue-detail', id, staffSocSurface && effectiveSocTenant ? { tenantId: effectiveSocTenant } : undefined)}
            >Open</AnchorButton>
            <Button
              size="sm"
              variant="secondary"
              loading={busy === `approve-${id}`}
              disabled={Boolean(approvalDisabledReason) || (busy !== '' && busy !== `approve-${id}`)}
              title={approvalDisabledReason || (busy && busy !== `approve-${id}` ? 'Another SOC action is in progress.' : undefined)}
              aria-describedby={approvalDisabledReason ? approvalControlId : undefined}
              onClick={(clickEvent) => {
                clickEvent.stopPropagation();
                void socAction(id, 'approve');
              }}
            >
              Quick approve
            </Button>
            {approvalDisabledReason ? <span className="muted text-xs" id={approvalControlId}>{approvalDisabledReason}</span> : null}
          </div>
        );
      }
    }
  ];

  async function socAction(requestId: string, action: string, body: Record<string, unknown> = {}) {
    if (!requestId) return null;
    const lifecycleConfirm: Record<string, string> = {
      approve: `Approve high-scale request ${requestId} and move it to approved?`,
      schedule: `Schedule high-scale request ${requestId} for execution?`,
      start: `Start high-scale execution for ${requestId}? Governed adapter traffic will begin.`,
      stop: `Stop high-scale execution for ${requestId} immediately?`,
      close: `Close high-scale request ${requestId} and finalize the test lifecycle?`
    };
    const lifecycleMessage = lifecycleConfirm[action];
    if (lifecycleMessage && !(await confirm({
      title: `${formatGovernanceStatusLabel(action)} high-scale request`,
      description: lifecycleMessage,
      confirmLabel: formatGovernanceStatusLabel(action),
      confirmTone: action === 'approve' || action === 'schedule' || action === 'start' ? 'default' : 'danger'
    }))) return null;
    setBusy(`${action}-${requestId}`);
    setError('');
    setMessage('');
    try {
      const payload = await socRequest(`/internal/soc/high-scale/${encodeURIComponent(requestId)}/${action}`, {
        method: 'POST',
        body
      });
      setActionOutput(payload, requestId);
      setMessage(`SOC ${action} completed for ${requestId}.`);
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

  async function setKillSwitch(active: boolean) {
    if (active) {
      if (!await confirm({ title: 'Activate tenant kill switch', description: 'Activate the tenant kill switch? New safe runs will be blocked, active safe runs cancelled, and governed high-scale execution stopped for this tenant.', confirmLabel: 'Activate kill switch' })) return;
    } else if (!await confirm({ title: 'Clear tenant kill switch', description: 'Clear the kill switch? Execution remains subject to authorization packs, approved windows, and all other safety gates.', confirmLabel: 'Clear kill switch', confirmTone: 'default' })) return;
    setBusy(active ? 'kill-on' : 'kill-off');
    setError('');
    setMessage('');
    try {
      const payload = await socRequest('/internal/soc/kill-switch', {
        method: 'POST',
        body: { active, reason: active ? 'SOC console activation' : 'SOC console cleared' }
      });
      setActionOutput(payload, '');
      setMessage(active ? 'Kill switch activated.' : 'Kill switch cleared.');
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

  const killSwitchActive = Boolean(data.state?.kill_switch?.active ?? data.state?.kill_switch?.enabled);
  const killSwitchReason = getString(data.state?.kill_switch as DataItem, ['reason'], 'tenant-scoped emergency stop');
  const scheduledCount = data.highScale.filter((item) => SOC_SCHEDULED_STATES.includes(normalizeHighScaleState(item))).length;
  const inReviewCount = data.highScale.filter((item) => SOC_REVIEW_STATES.includes(normalizeHighScaleState(item))).length;
  const runningCount = data.highScale.filter((item) => SOC_RUNNING_STATES.includes(normalizeHighScaleState(item))).length;
  const openFindingsCount = Number(data.state?.open_findings ?? data.findings.filter(isFindingOpen).length) || 0;
  const goNoGoGates = buildSocGoNoGoGates(data.highScale, { killSwitchActive, runningCount, openFindings: openFindingsCount });
  const providerContactRows = buildProviderContactRows(data.highScale);
  const executionTimeline = buildSocExecutionTimeline(data.highScale);
  const crossTenantHighScale = staffSocSurface ? buildSocCrossTenantRows(socQueue.items) : [];
  const executionTenantMissing = staffSocSurface && !effectiveSocTenant;
  const activateKillSwitchReason = executionTenantMissing
    ? 'Select an execution tenant before activating the kill switch.'
    : killSwitchActive
      ? 'The tenant kill switch is already active.'
      : busy && busy !== 'kill-on'
        ? 'Another SOC action is in progress.'
        : '';
  const clearKillSwitchReason = executionTenantMissing
    ? 'Select an execution tenant before clearing the kill switch.'
    : !killSwitchActive
      ? 'The tenant kill switch is already clear.'
      : busy && busy !== 'kill-off'
        ? 'Another SOC action is in progress.'
        : '';
  const activeTenantCount = new Set(
    crossTenantHighScale.map((row) => row.tenantId).filter((id) => id && id !== '—')
  ).size;
  const tenantSelectOptions = useMemo(() => {
    const names = new Map(socQueue.tenants.map((tenant) => [getString(tenant, ['tenant_id'], ''), getString(tenant, ['name'], '')]));
    const fromCross = crossTenantHighScale.map((row) => row.tenantId).filter((id) => id && id !== '—');
    const ids = [...new Set([...fromCross, ...names.keys(), effectiveSocTenant].filter(Boolean))];
    return [
      { value: '', label: 'Select execution tenant…' },
      ...ids.map((id) => ({ value: id, label: names.get(id) ? `${names.get(id)} (${id})` : id }))
    ];
  }, [crossTenantHighScale, effectiveSocTenant, socQueue.tenants]);

  if (!isSoc) {
    return (
      <div className="content">
        <PageHeader
          route="internal-soc"
          eyebrow={staffSocSurface ? 'Staff SOC execution plane' : 'SOC execution plane'}
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

  return (
    <div className="content">
      <PageHeader
        route="internal-soc"
        eyebrow={staffSocSurface ? 'Staff SOC execution plane' : 'Tenant SOC execution plane'}
        description="Governed request review, authorization custody, provider coordination, bounded execution limits, and tenant emergency stop controls."
        actions={staffSocSurface ? <Badge tone="warn">Privileged staff plane</Badge> : <Badge tone="muted">SOC role</Badge>}
      />
      {staffSocSurface ? (
        <Card>
          <CardHeader>
            <CardTitle>Execution tenant</CardTitle>
            <CardDescription>
              Staff SOC actions are tenant-scoped. Select a tenant before kill switch or queue mutations, or open a cross-tenant request with ?tenant=.
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
          </CardContent>
        </Card>
      ) : null}
      <div className={killSwitchActive ? 'callout warn' : 'callout info'}>
        {killSwitchActive ? <Siren size={18} aria-hidden="true" /> : <ShieldCheck size={18} aria-hidden="true" />}
        <span>
          {killSwitchActive
            ? 'Kill switch is active — new safe runs are blocked, active safe runs are cancelled, and governed high-scale execution is stopped for this tenant.'
            : 'Kill switch is clear. Safe checks remain bounded; high-scale execution still requires accepted authorization, provider approval when required, and an approved schedule.'}
        </span>
      </div>
      <div className="metric-grid four">
        {staffSocSurface ? (
          <MetricCard label="Active tenants" value={formatNumber(activeTenantCount)} sub="with governed requests" icon={Users} tone={activeTenantCount > 0 ? 'info' : 'muted'} />
        ) : (
          <MetricCard label="Queue" value={formatNumber(data.highScale.length)} sub="governed requests" icon={ShieldCheck} tone={data.highScale.length > 0 ? 'info' : 'muted'} />
        )}
        <MetricCard label="Scheduled" value={formatNumber(scheduledCount)} sub="approved or scheduled" icon={CalendarClock} tone={scheduledCount > 0 ? 'info' : 'muted'} />
        <MetricCard label="In review" value={formatNumber(inReviewCount)} sub="awaiting SOC decision" icon={ClipboardList} tone={inReviewCount > 0 ? 'warn' : 'muted'} />
        <MetricCard label="Kill switch" value={killSwitchActive ? 'Armed' : 'Clear'} sub="tenant emergency stop" icon={Siren} tone={killSwitchActive ? 'danger' : 'success'} />
      </div>
      <PageContextSummary>
        {staffSocSurface ? (
          <>
            Cross-tenant <span className="tabular-nums">{formatNumber(crossTenantHighScale.length)}</span> governed requests across{' '}
            <span className="tabular-nums">{formatNumber(activeTenantCount)}</span> tenants ·{' '}
          </>
        ) : null}
        Queue <span className="tabular-nums">{formatNumber(data.highScale.length)}</span> governed requests ·{' '}
        <span className="tabular-nums">{formatNumber(openFindingsCount)}</span> open findings
      </PageContextSummary>
      <GovernanceFeedbackBanner message={message} error={error} />
      <div className="dash-grid">
        <Card density="compact">
          <CardHeader>
            <CardTitle>Kill switch</CardTitle>
            <CardDescription>Tenant-scoped emergency stop across bounded safe runs and governed high-scale adapter execution.</CardDescription>
          </CardHeader>
          <CardContent className="stack-tight">
            <div className="kv-list">
              <KvField label="Status">
                <Badge tone={killSwitchActive ? 'danger' : 'success'}>{killSwitchActive ? 'Armed' : 'Clear'}</Badge>
              </KvField>
              <KvField label="Reason">{killSwitchReason}</KvField>
            </div>
            <div className="row-actions">
              <Button
                size="sm"
                variant="danger"
                loading={busy === 'kill-on'}
                disabled={Boolean(activateKillSwitchReason)}
                title={activateKillSwitchReason || undefined}
                aria-describedby={activateKillSwitchReason ? 'kill-switch-disabled-reason' : undefined}
                onClick={() => void setKillSwitch(true)}
              >Activate</Button>
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
            {(activateKillSwitchReason || clearKillSwitchReason) ? (
              <p className="muted text-xs" id="kill-switch-disabled-reason">
                {killSwitchActive ? activateKillSwitchReason : clearKillSwitchReason}
              </p>
            ) : null}
            <details className="disclosure">
              <summary>Validated emergency-stop sequence · {KILL_SWITCH_VALIDATED_SEQUENCE.length} custody-recorded steps</summary>
              <div className="timeline-list">
                {KILL_SWITCH_VALIDATED_SEQUENCE.map((step) => (
                  <div key={step}>
                    <span aria-hidden="true" />
                    <div><strong className="mono">{step}</strong></div>
                  </div>
                ))}
              </div>
            </details>
          </CardContent>
        </Card>
        <Card density="compact">
          <CardHeader>
            <CardTitle>Go / No-Go</CardTitle>
            <CardDescription>Pre-flight gates computed from the current governed queue and tenant safety state.</CardDescription>
          </CardHeader>
          <CardContent className="kv-list">
            {goNoGoGates.map((gate) => (
              <KvField key={gate.key} label={gate.label}>
                <Badge tone={gate.tone}>{gate.status}</Badge>
              </KvField>
            ))}
          </CardContent>
        </Card>
      </div>
      {staffSocSurface ? (
        <Card>
          <CardHeader>
            <CardTitle>Cross-tenant execution</CardTitle>
            <CardDescription>Governed high-scale requests across all customer tenants, read from the audited staff SOC queue. Open a request for the full lifecycle workspace.</CardDescription>
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
            ? 'Governed requests for the active execution-tenant context. Open a request for the full lifecycle workspace; quick approve is available when the authorization pack is accepted.'
            : 'Open a request for the full lifecycle workspace. Quick approve is available here only when the authorization pack is accepted.'}</CardDescription>
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
              <EmptyState icon={ShieldCheck} title="No high-scale requests." body="Customer requests appear here after intake and authorization-pack review." />
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
              <EmptyState icon={Activity} title="No execution timeline yet." body="Lifecycle events appear after SOC approval, scheduling, or execution actions." />
            ) : (
              <div className="timeline-list">
                {executionTimeline.map((event, index) => (
                  <div key={event.key}>
                    <span>{index + 1}</span>
                    <div>
                      <strong>{formatGovernanceStatusLabel(event.action)} · <span className="mono">{event.requestId}</span></strong>
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
              empty={<EmptyState icon={Users} title="No provider or emergency contacts." body="Contacts appear after authorization-pack intake declares provider and emergency contacts." />}
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
