import { useEffect, useMemo, useState, type FormEvent } from 'react';
import { Lock, ShieldCheck } from 'lucide-react';
import { Badge } from '../ui/badge';
import { AnchorButton, Button } from '../ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../ui/card';
import { Select, type SelectOption } from '../ui/select';
import { DataTable, type TableColumn } from '../ui/table';
import { ConfirmModal, formatMutationSuccessMessage, renderFriendlyEmptyState } from '../../lib/crud-ui';
import { PortalLoadingSkeleton } from '../../lib/empty-from-api';
import {
  AUTHORIZATION_ARTIFACT_CATALOG,
  GOVERNED_HIGH_SCALE_SCENARIOS,
  buildMetadataArtifactUploadBody,
  providerApprovalRequired
} from '../../lib/high-scale';
import { sha256CanonicalJsonForCustody } from '../../lib/custody';
import { requestJson } from '../../lib/api';
// @ts-ignore Plain ESM keeps status labels directly testable with node:test.
import { plainCodeLabel } from '../../lib/plain-language.mjs';
import { apiErrorMessage } from '../../lib/error-messages';
import { sessionHasPermission } from '../../lib/dataset-access.mjs';
import { buildDetailHref } from '../../lib/route-params';
import type { DataItem, PortalConfig, PortalData, Session } from '../../lib/types';
import { formatDate, formatNumber } from '../../lib/utils';

const HIGH_SCALE_SCENARIO_OPTIONS: SelectOption[] = GOVERNED_HIGH_SCALE_SCENARIOS.map((scenario) => ({
  value: scenario.id,
  label: `${scenario.label} (${scenario.id})`
}));

const HIGH_SCALE_CRITICALITY_OPTIONS: SelectOption[] = [
  { value: 'medium', label: 'Medium' },
  { value: 'high', label: 'High' },
  { value: 'critical', label: 'Critical' }
];

const HIGH_SCALE_ENVIRONMENT_OPTIONS: SelectOption[] = [
  { value: 'staging', label: 'Staging' },
  { value: 'production', label: 'Production' }
];

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

function governedLimitDisplay(item: DataItem) {
  const familyId = Array.isArray(item.requested_scenario_families)
    ? String(item.requested_scenario_families[0] ?? '')
    : '';
  const scenario = GOVERNED_HIGH_SCALE_SCENARIOS.find((entry) => entry.id === familyId);
  const limits = item.requested_limits && typeof item.requested_limits === 'object' && !Array.isArray(item.requested_limits)
    ? item.requested_limits as DataItem
    : {};
  const rate = scenario && typeof limits[scenario.limit.field] === 'number'
    ? `${limits[scenario.limit.field]} ${scenario.limit.unit}`
    : '';
  const duration = typeof limits.max_duration_minutes === 'number'
    ? `${limits.max_duration_minutes} minutes`
    : '';
  return [rate, duration].filter(Boolean).join(' · ') || '—';
}

function targetGroupDisplayName(data: PortalData, groupId: string) {
  const group = data.targetGroups.find((item) => getString(item, ['id'], '') === groupId);
  return getString(group ?? {}, ['name', 'title'], groupId || '—');
}

function datetimeLocalValue(offsetHours: number) {
  const date = new Date(Date.now() + offsetHours * 60 * 60 * 1000);
  const pad = (value: number) => String(value).padStart(2, '0');
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(date.getHours())}:${pad(date.getMinutes())}`;
}

function isoFromLocalDatetime(value: FormDataEntryValue | null) {
  const raw = String(value ?? '').trim();
  if (!raw) return '';
  const date = new Date(raw);
  return Number.isNaN(date.getTime()) ? '' : date.toISOString();
}

function packBadgeTone(overall: string): 'success' | 'warn' | 'danger' | 'muted' {
  const normalized = overall.trim().toLowerCase();
  if (normalized === 'accepted') return 'success';
  if (normalized === 'missing' || !normalized || normalized === '—') return 'danger';
  return 'warn';
}

function authorizationPackProgress(item: DataItem) {
  const raw = item.authorization_pack_status;
  const status = raw && typeof raw === 'object' && !Array.isArray(raw) ? raw as DataItem : {};
  const overall = getString(status, ['overall'], 'missing');
  const requirements = Array.isArray(status.requirements) ? status.requirements as DataItem[] : [];
  const accepted = requirements.filter((requirement) => getString(requirement, ['status'], '').toLowerCase() === 'accepted').length;
  return {
    overall,
    label: requirements.length > 0 && overall.toLowerCase() !== 'accepted'
      ? `${formatNumber(accepted)}/${formatNumber(requirements.length)} accepted`
      : overall.replace(/_/g, ' '),
    detail: requirements.length > 0
      ? `${formatNumber(accepted)} of ${formatNumber(requirements.length)} required authorization artifacts accepted`
      : `Authorization pack status: ${overall}`
  };
}

function providerApprovalDisplay(item: DataItem): { label: string; detail: string; tone: 'success' | 'warn' | 'danger' | 'muted' } {
  if (!providerApprovalRequired(item)) {
    return { label: 'not required', detail: 'No provider approval requirement declared', tone: 'muted' };
  }
  const checklist = Array.isArray(item.provider_approval_checklist)
    ? (item.provider_approval_checklist as DataItem[]).filter((entry) => entry.required !== false)
    : [];
  if (checklist.length === 0) {
    return { label: 'missing', detail: 'Provider approval evidence has not been attached', tone: 'danger' };
  }
  const statuses = checklist.map((entry) => getString(entry, ['status'], 'missing').toLowerCase());
  const providers = checklist
    .map((entry) => getString(entry, ['provider_name'], ''))
    .filter((name) => name && name !== '—')
    .join(', ');
  if (statuses.every((status) => status === 'accepted')) {
    return { label: 'accepted', detail: providers || 'All required provider approvals accepted', tone: 'success' };
  }
  const blocking = statuses.find((status) => ['rejected', 'expired'].includes(status));
  if (blocking) return { label: blocking.replace(/_/g, ' '), detail: providers || 'Provider approval requires attention', tone: 'danger' };
  const pending = statuses.find((status) => status !== 'accepted') ?? 'pending';
  return { label: pending.replace(/_/g, ' '), detail: providers || 'Provider approval is not yet accepted', tone: 'warn' };
}

function SocQueueStat({ label, value }: { label: string; value: number }) {
  return (
    <div>
      <span className="muted">{label}</span>
      <strong className="tabular-nums">{formatNumber(value)}</strong>
    </div>
  );
}

function stateBadgeTone(state: string): 'success' | 'warn' | 'danger' | 'info' | 'muted' {
  const normalized = state.trim().toLowerCase();
  if (['approved', 'scheduled'].includes(normalized)) return 'info';
  if (['running', 'executing', 'active', 'started'].includes(normalized)) return 'danger';
  if (['submitted', 'soc_review', 'under_review'].includes(normalized)) return 'warn';
  if (['closed', 'completed', 'cancelled', 'canceled'].includes(normalized)) return 'success';
  return 'muted';
}

type RunsSocGateProps = {
  data: PortalData;
  config: PortalConfig;
  session: Session;
  onRefresh: () => Promise<void>;
  onMessage: (message: string) => void;
  onError: (error: string) => void;
  busy: string;
  setBusy: (value: string) => void;
  requestFormOpen?: boolean;
  onRequestFormOpenChange?: (open: boolean) => void;
};

export function RunsSocGatePanel({
  data,
  config,
  session,
  onRefresh,
  onMessage,
  onError,
  busy,
  setBusy,
  requestFormOpen,
  onRequestFormOpenChange
}: RunsSocGateProps) {
  const [queue, setQueue] = useState<DataItem[] | null>(null);
  const [queueError, setQueueError] = useState('');
  const [queueLoading, setQueueLoading] = useState(true);
  const [queueReloadKey, setQueueReloadKey] = useState(0);
  const [internalRequestForm, setInternalRequestForm] = useState(false);
  const showRequestForm = requestFormOpen ?? internalRequestForm;
  const setShowRequestForm = onRequestFormOpenChange ?? setInternalRequestForm;
  const [packRequestId, setPackRequestId] = useState('');
  const [targetGroupId, setTargetGroupId] = useState(() => getString(data.targetGroups[0] ?? {}, ['id'], ''));
  const [environment, setEnvironment] = useState('staging');
  const [criticality, setCriticality] = useState('high');
  const [scenarioFamilyId, setScenarioFamilyId] = useState(GOVERNED_HIGH_SCALE_SCENARIOS[0]?.id ?? '');
  const [deliveryPatternId, setDeliveryPatternId] = useState(
    GOVERNED_HIGH_SCALE_SCENARIOS[0]?.deliveryPatterns[0]?.id ?? ''
  );
  const selectedScenario = GOVERNED_HIGH_SCALE_SCENARIOS.find((scenario) => scenario.id === scenarioFamilyId);
  const deliveryPatternOptions: SelectOption[] = (selectedScenario?.deliveryPatterns ?? []).map((pattern) => ({
    value: pattern.id,
    label: `${pattern.label} (${pattern.id})`
  }));
  // P0#2: customers are non-staff principals. The queue item must open the customer
  // high-scale detail surface (HighScaleDetailView), not the staff SOC gate.
  const isStaffPrincipal = session.principal === 'staff';
  const canRequestHighScale = sessionHasPermission(session, 'high_scale:request');

  const targetGroupOptions: SelectOption[] = [
    { value: '', label: 'Select declared scope' },
    ...data.targetGroups.map((group) => ({
      value: getString(group, ['id']),
      label: getString(group, ['name', 'id'])
    }))
  ];

  const summary = useMemo(() => {
    const items = queue ?? [];
    const submitted = items.filter((item) => ['submitted', 'soc_review', 'under_review'].includes(getString(item, ['state'], '').toLowerCase())).length;
    const scheduled = items.filter((item) => getString(item, ['state'], '').toLowerCase() === 'scheduled').length;
    const packPending = items.filter((item) => getNestedString(item, ['authorization_pack_status', 'overall'], 'missing').toLowerCase() !== 'accepted').length;
    return { total: items.length, submitted, scheduled, packPending };
  }, [queue]);

  useEffect(() => {
    let cancelled = false;
    setQueueLoading(true);
    setQueueError('');
    requestJson(config, session, '/v1/high-scale-requests?scope=my-tenant')
      .then((payload) => {
        if (cancelled) return;
        const items = Array.isArray((payload as { items?: unknown }).items)
          ? (payload as { items: DataItem[] }).items
          : Array.isArray(payload) ? payload as DataItem[] : [];
        setQueue(items);
      })
      .catch((err) => {
        if (!cancelled) {
          setQueue(null);
          setQueueError(err instanceof Error ? err.message : 'Could not load SOC-gated queue.');
        }
      })
      .finally(() => {
        if (!cancelled) setQueueLoading(false);
      });
    return () => { cancelled = true; };
  }, [config, session, data.highScale.length, queueReloadKey]);

  async function runAction<T>(label: string, action: () => Promise<T>, success: string) {
    setBusy(label);
    onError('');
    onMessage('');
    try {
      const result = await action();
      onMessage(formatMutationSuccessMessage(success, result));
      await onRefresh();
      const payload = await requestJson(config, session, '/v1/high-scale-requests?scope=my-tenant') as { items?: DataItem[] };
      setQueue(Array.isArray(payload.items) ? payload.items : []);
      return result;
    } catch (err) {
      const payload = (err as Error & { payload?: unknown }).payload as { missing?: string[] } | undefined;
      const missing = Array.isArray(payload?.missing) ? ` Missing: ${payload.missing.join(', ')}.` : '';
      onError(`${apiErrorMessage(err, 'High-scale action failed.')}${missing}`);
      return null;
    } finally {
      setBusy('');
    }
  }

  async function handleCreateRequest(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!canRequestHighScale) return;
    const formEl = event.currentTarget;
    const form = new FormData(formEl);
    if (form.get('scope_confirmation') !== 'on') {
      onError('Confirm that declared scope and authorization metadata are accurate before submitting.');
      return;
    }
    if (!selectedScenario || !selectedScenario.deliveryPatterns.some((pattern) => pattern.id === deliveryPatternId)) {
      onError('Select a governed scenario family and one of its compatible delivery patterns.');
      return;
    }
    const scenarioLimit = Number(form.get(selectedScenario.limit.field));
    const maxDurationMinutes = Number(form.get('max_duration_minutes'));
    const windowStart = isoFromLocalDatetime(form.get('window_start'));
    const windowEnd = isoFromLocalDatetime(form.get('window_end'));
    if (
      !Number.isFinite(scenarioLimit)
      || scenarioLimit < selectedScenario.limit.min
      || scenarioLimit > selectedScenario.limit.max
      || (selectedScenario.limit.step === 1 && !Number.isInteger(scenarioLimit))
      || !Number.isFinite(maxDurationMinutes)
      || !Number.isInteger(maxDurationMinutes)
      || maxDurationMinutes < 1
      || maxDurationMinutes > 720
    ) {
      onError('Enter numeric governed limits within the displayed units and bounds.');
      return;
    }
    if (!windowStart || !windowEnd || new Date(windowStart).getTime() >= new Date(windowEnd).getTime()) {
      onError('Choose a valid requested window whose end is after its start.');
      return;
    }
    const body = {
      target_group_id: String(form.get('target_group_id') ?? '').trim(),
      objective: String(form.get('objective') ?? '').trim(),
      environment: String(form.get('environment') ?? 'staging').trim(),
      business_criticality: String(form.get('business_criticality') ?? 'high').trim(),
      requested_scenario_families: [selectedScenario.id],
      delivery_patterns: [deliveryPatternId],
      requested_limits: {
        [selectedScenario.limit.field]: scenarioLimit,
        max_duration_minutes: maxDurationMinutes
      },
      stop_criteria: { abort_on_customer_signal: true, max_error_rate_pct: 5 },
      abort_criteria: { threshold: 'error_rate_above_5pct', auto_stop: true },
      requested_window: {
        window_start: windowStart,
        window_end: windowEnd,
        timezone: String(form.get('timezone') ?? 'UTC').trim() || 'UTC'
      },
      emergency_contacts: [{
        name: String(form.get('contact_name') ?? '').trim(),
        contact: String(form.get('contact') ?? '').trim()
      }],
      provider_context: {
        provider_name: String(form.get('provider_name') ?? '').trim(),
        requires_provider_approval: true
      },
      scope_confirmation: true
    };
    const created = await runAction('create-high-scale', () => requestJson(config, session, '/v1/high-scale-requests', {
      method: 'POST',
      body
    }), 'SOC-gated request submitted for review.');
    if (created) {
      setShowRequestForm(false);
      formEl.reset();
    }
  }

  async function uploadPackArtifact(request: DataItem) {
    if (!canRequestHighScale) return;
    const requestId = getString(request, ['id'], '');
    if (!requestId) return;
    const filename = 'authorization-pack-metadata.json';
    // Custody digest is computed over this canonical metadata-only payload.
    const packContent = {
      artifact_type: 'customer_authorization_letter',
      request_id: requestId,
      filename,
      target_group_id: getString(request, ['target_group_id'], ''),
      requested_window: request.requested_window ?? null,
      requested_limits: request.requested_limits ?? null,
      requested_scenario_families: request.requested_scenario_families ?? [],
      delivery_patterns: request.delivery_patterns ?? [],
      emergency_contacts: request.emergency_contacts ?? [],
      abort_criteria: request.abort_criteria ?? null,
      provider_context: request.provider_context ?? null
    };
    let contentSha256: string;
    try {
      contentSha256 = await sha256CanonicalJsonForCustody(packContent);
    } catch {
      onError('Cannot compute the pack content digest: Web Crypto (crypto.subtle) is unavailable in this context.');
      return;
    }
    const body = buildMetadataArtifactUploadBody(request, 'customer_authorization_letter', {
      filename,
      content_sha256: contentSha256,
      custody_id: `cust_${requestId}`
    });
    await runAction(`pack-${requestId}`, () => requestJson(config, session, `/v1/high-scale-requests/${encodeURIComponent(requestId)}/artifacts`, {
      method: 'POST',
      body
    }), 'Customer authorization letter metadata uploaded for SOC review.');
    setPackRequestId('');
  }

  const columns: TableColumn<DataItem>[] = [
    {
      key: 'request',
      label: 'Request',
      render: (item) => {
        const requestId = getString(item, ['id'], '');
        const requestLabel = getString(item, ['objective', 'reason', 'name'], 'High-scale validation request');
        // §4.7: customers see their own high-scale requests INLINE (all state is in this row);
        // the queue-detail SOC workspace is staff-only, so customers do NOT navigate there
        // (avoids the staff-gated "access denied" dead-end). Staff open the workspace from here.
        if (!isStaffPrincipal) {
          return <span title={requestId || undefined}>{requestLabel}</span>;
        }
        return (
          <AnchorButton
            variant="ghost"
            href={buildDetailHref('queue-detail', requestId)}
            aria-label={`Open SOC workspace for request ${requestId}`}
          >
            {requestLabel}
          </AnchorButton>
        );
      }
    },
    { key: 'policy', label: 'Policy', render: (item) => { const policy = getString(item, ['policy_id'], ''); const scenario = getString(item, ['requested_scenario_families'], 'soc_gated'); return <span title={policy || undefined}>{policy ? 'Scheduled policy' : plainCodeLabel(scenario)}</span>; } },
    { key: 'group', label: 'Target group', render: (item) => targetGroupDisplayName(data, getString(item, ['target_group_id'])) },
    { key: 'limits', label: 'Governed limits', render: (item) => governedLimitDisplay(item) },
    {
      key: 'pack',
      label: 'Authorization pack',
      render: (item) => {
        const pack = authorizationPackProgress(item);
        return <Badge tone={packBadgeTone(pack.overall)} title={pack.detail}>{pack.label}</Badge>;
      }
    },
    {
      key: 'provider',
      label: 'Provider approval',
      render: (item) => {
        const provider = providerApprovalDisplay(item);
        return <Badge tone={provider.tone} title={provider.detail}>{provider.label}</Badge>;
      }
    },
    {
      key: 'state',
      label: 'State',
      render: (item) => {
        const state = getString(item, ['state']);
        return <Badge tone={stateBadgeTone(state)} title={`Recorded request state: ${plainCodeLabel(state)}`}>{plainCodeLabel(state)}</Badge>;
      }
    },
    {
      key: 'window',
      label: 'Window',
      render: (item) => {
        const start = getNestedString(item, ['requested_window', 'window_start'], '');
        const scheduled = getNestedString(item, ['scheduled_window', 'window_start'], '');
        const value = scheduled && scheduled !== '—' ? scheduled : start;
        return value && value !== '—' ? formatDate(value) : 'unscheduled';
      }
    },
    {
      key: 'actions',
      label: 'Action',
      render: (item) => {
        const id = getString(item, ['id'], '');
        const pack = getNestedString(item, ['authorization_pack_status', 'overall'], 'missing').toLowerCase();
        if (pack !== 'accepted') {
          return (
            <div className="stack-tight">
              <AnchorButton
                size="sm"
                variant="ghost"
                href={buildDetailHref('queue-detail', id)}
                aria-label={`Complete all authorization artifacts for request ${id}`}
              >
                Open pack
              </AnchorButton>
              {canRequestHighScale ? (
                <Button
                  size="sm"
                  variant="secondary"
                  disabled={busy !== '' && busy !== `pack-${id}`}
                  title={busy && busy !== `pack-${id}` ? 'Another high-scale action is in progress.' : 'Attach customer authorization letter metadata; remaining artifacts stay visible in request detail.'}
                  onClick={() => setPackRequestId(id)}
                >
                  Attach letter
                </Button>
              ) : null}
            </div>
          );
        }
        return <span className="muted mono">awaiting SOC decision</span>;
      }
    }
  ];

  const missingScopeReason = data.targetGroups.length === 0
    ? 'Create a declared target group before requesting governed high-scale validation.'
    : '';
  const requestToggleDisabledReason = missingScopeReason || (busy ? 'Wait for the current run or high-scale action to finish.' : '');
  const requestSubmitDisabledReason = missingScopeReason || (busy && busy !== 'create-high-scale'
    ? 'Another run or high-scale action is in progress.'
    : '');

  return (
    <>
      <Card className="runs-soc-gate" density="compact">
        <CardHeader>
          <div>
            <CardTitle>Governed high-scale queue</CardTitle>
            <CardDescription>Customer intake and authorization status. Approval, scheduling, execution, and emergency stop remain SOC-only.</CardDescription>
          </div>
          {canRequestHighScale ? (
            <Button
              size="sm"
              variant="secondary"
              aria-expanded={showRequestForm}
              aria-controls={showRequestForm ? 'high-scale-request-intake' : undefined}
              disabled={Boolean(requestToggleDisabledReason)}
              title={requestToggleDisabledReason || undefined}
              onClick={() => setShowRequestForm(!showRequestForm)}
            >
              {showRequestForm ? 'Close intake' : 'New request'}
            </Button>
          ) : null}
        </CardHeader>
        <CardContent className="stack-tight">
          <div className="callout callout-soc" role="note" aria-labelledby="soc-gate-callout-title">
            <div className="callout-icon" aria-hidden="true">
              <Lock size={18} />
            </div>
            <div className="callout-body">
              <div className="callout-title" id="soc-gate-callout-title">Safe checks and high-scale requests use separate execution boundaries</div>
              <p className="callout-desc">
                Safe checks remain customer-runnable only within bounded catalog limits. This queue submits a request—it never starts high-scale traffic.
                SOC must accept every authorization artifact and required provider approval, schedule the window, and retain kill-switch control.
              </p>
            </div>
          </div>
          <div className="soc-queue-summary" aria-label="Governed high-scale queue summary">
            <SocQueueStat label="In review" value={summary.submitted} />
            <SocQueueStat label="Scheduled" value={summary.scheduled} />
            <SocQueueStat label="Pack pending" value={summary.packPending} />
          </div>
          {missingScopeReason ? (
            <div className="callout info" role="note">
              <ShieldCheck size={18} aria-hidden="true" />
              <span>{missingScopeReason}</span>
            </div>
          ) : null}
          {queueLoading ? <PortalLoadingSkeleton rows={2} /> : null}
          {queueError ? (
            <div className="form-banner error" role="alert">
              <span>{queueError}</span>
              <Button size="sm" variant="secondary" onClick={() => setQueueReloadKey((key) => key + 1)}>Retry queue</Button>
            </div>
          ) : null}
          {!queueLoading && !queueError ? (
            <DataTable
              columns={columns}
              items={queue ?? []}
              empty={renderFriendlyEmptyState({
                icon: ShieldCheck,
                title: 'No SOC-gated requests in queue.',
                body: 'Submit a governed request when you need high-scale validation under SOC oversight.',
                actionLabel: canRequestHighScale ? 'Request SOC-gated run' : undefined,
                onAction: canRequestHighScale ? () => setShowRequestForm(true) : undefined
              })}
            />
          ) : null}
        </CardContent>
      </Card>

      {canRequestHighScale && showRequestForm ? (
        <Card id="high-scale-request-intake" raised>
          <CardHeader>
            <div>
              <CardTitle>Request governed high-scale validation</CardTitle>
              <CardDescription>Submit bounded scope, scheduling, safety, and custody metadata for SOC review. This action does not execute traffic.</CardDescription>
            </div>
            <Badge tone="warn">Request only</Badge>
          </CardHeader>
          <CardContent>
            <form className="product-form" onSubmit={handleCreateRequest} aria-busy={busy === 'create-high-scale' || undefined}>
              <fieldset disabled={busy !== ''}>
                <legend>Scope and intent</legend>
                <input type="hidden" name="target_group_id" value={targetGroupId} />
                <Select label="Declared target group" value={targetGroupId} options={targetGroupOptions} disabled={data.targetGroups.length === 0 || busy !== ''} onChange={setTargetGroupId} />
                <Select label="Environment" name="environment" value={environment} options={HIGH_SCALE_ENVIRONMENT_OPTIONS} disabled={busy !== ''} onChange={setEnvironment} />
                <Select label="Business criticality" name="business_criticality" value={criticality} options={HIGH_SCALE_CRITICALITY_OPTIONS} onChange={setCriticality} disabled={busy !== ''} />
                <label className="full"><span>Objective</span><textarea name="objective" rows={3} required disabled={busy !== ''} placeholder="Describe the evidence-backed validation objective and expected outcome." /></label>
              </fieldset>

              <fieldset disabled={busy !== ''}>
                <legend>Requested schedule</legend>
                <label><span>Window start</span><input name="window_start" type="datetime-local" defaultValue={datetimeLocalValue(24)} required disabled={busy !== ''} /></label>
                <label><span>Window end</span><input name="window_end" type="datetime-local" defaultValue={datetimeLocalValue(48)} required disabled={busy !== ''} /></label>
                <label><span>Timezone</span><input name="timezone" defaultValue="UTC" required disabled={busy !== ''} aria-describedby="high-scale-timezone-help" /></label>
                <p className="muted text-xs" id="high-scale-timezone-help">The requested window is stored as exact timestamps together with this coordination timezone.</p>
              </fieldset>

              <fieldset disabled={busy !== ''}>
                <legend>Governed execution envelope</legend>
                <Select
                  label="Scenario family"
                  name="requested_scenario_family"
                  value={scenarioFamilyId}
                  options={HIGH_SCALE_SCENARIO_OPTIONS}
                  disabled={busy !== ''}
                  onChange={(value) => {
                    const scenario = GOVERNED_HIGH_SCALE_SCENARIOS.find((entry) => entry.id === value);
                    setScenarioFamilyId(value);
                    setDeliveryPatternId(scenario?.deliveryPatterns[0]?.id ?? '');
                  }}
                />
                <Select
                  label="Compatible delivery pattern"
                  name="delivery_pattern"
                  value={deliveryPatternId}
                  options={deliveryPatternOptions}
                  disabled={busy !== '' || !selectedScenario}
                  onChange={setDeliveryPatternId}
                />
                {selectedScenario ? (
                  <label>
                    <span>{selectedScenario.limit.label} ({selectedScenario.limit.unit})</span>
                    <input
                      key={selectedScenario.id}
                      name={selectedScenario.limit.field}
                      type="number"
                      min={selectedScenario.limit.min}
                      max={selectedScenario.limit.max}
                      step={selectedScenario.limit.step}
                      defaultValue={selectedScenario.limit.defaultValue}
                      required
                      disabled={busy !== ''}
                      aria-describedby="high-scale-limit-help"
                    />
                    <small className="muted text-xs" id="high-scale-limit-help">
                      Allowed request bound: {formatNumber(selectedScenario.limit.min)}–{formatNumber(selectedScenario.limit.max)} {selectedScenario.limit.unit}.
                    </small>
                  </label>
                ) : null}
                <label>
                  <span>Maximum duration (minutes)</span>
                  <input name="max_duration_minutes" type="number" min={1} max={720} step={1} defaultValue={45} required disabled={busy !== ''} />
                </label>
                <div className="callout info full" role="note">
                  <ShieldCheck size={18} aria-hidden="true" />
                  <span>Submitted limits are authorization ceilings, not execution instructions. Customer signal or error rate above 5% requests automatic stop; the SOC kill switch remains authoritative.</span>
                </div>
              </fieldset>

              <fieldset disabled={busy !== ''}>
                <legend>Coordination and approvals</legend>
                <label><span>Provider</span><input name="provider_name" placeholder="CDN, WAF, carrier, or lab provider" required disabled={busy !== ''} /></label>
                <label><span>Emergency contact</span><input name="contact_name" placeholder="Named on-call owner" required disabled={busy !== ''} /></label>
                <label><span>Contact path</span><input name="contact" placeholder="Auditable email or phone path" required disabled={busy !== ''} /></label>
                <div className="callout info full" role="note"><ShieldCheck size={18} aria-hidden="true" /><span>Provider approval evidence is required for the named provider before SOC approval.</span></div>
              </fieldset>

              <details className="disclosure full">
                <summary>Authorization pack · {AUTHORIZATION_ARTIFACT_CATALOG.length} required artifact types</summary>
                <div className="kv-list kv-list--compact">
                  {AUTHORIZATION_ARTIFACT_CATALOG.map((artifact) => (
                    <div key={artifact.artifact_type}>
                      <span>{artifact.title}</span>
                      <strong>{artifact.purpose}</strong>
                    </div>
                  ))}
                </div>
              </details>

              <label className="check-row full">
                <input name="scope_confirmation" type="checkbox" required disabled={busy !== ''} />
                <span>I confirm the declared scope, requested limits, authorization metadata, provider coordination, and emergency contacts are accurate.</span>
              </label>
              {requestSubmitDisabledReason ? <p className="muted text-xs full" id="high-scale-submit-disabled-reason">{requestSubmitDisabledReason}</p> : null}
              <div className="form-actions full">
                <Button
                  type="submit"
                  loading={busy === 'create-high-scale'}
                  disabled={Boolean(requestSubmitDisabledReason)}
                  title={requestSubmitDisabledReason || undefined}
                  aria-describedby={requestSubmitDisabledReason ? 'high-scale-submit-disabled-reason' : undefined}
                >Submit for SOC review</Button>
                <Button type="button" variant="ghost" disabled={busy !== ''} onClick={() => setShowRequestForm(false)}>Cancel</Button>
              </div>
            </form>
          </CardContent>
        </Card>
      ) : null}

      <ConfirmModal
        open={canRequestHighScale && Boolean(packRequestId)}
        title="Attach customer authorization letter"
        description={(
          <>
            <p>Attach metadata-only customer authorization letter evidence for request <code>{packRequestId}</code>.</p>
            <p className="muted">This writes a custody digest and audit entry for one required artifact. Open request detail to complete ownership, contacts, stop criteria, plans, business/legal approvals, scope/rate, abort criteria, and provider approval.</p>
          </>
        )}
        confirmLabel="Attach letter metadata"
        busy={busy === `pack-${packRequestId}`}
        onCancel={() => setPackRequestId('')}
        onConfirm={() => {
          const request = (queue ?? []).find((item) => getString(item, ['id']) === packRequestId)
            ?? data.highScale.find((item) => getString(item, ['id']) === packRequestId);
          if (request) void uploadPackArtifact(request);
        }}
      />
    </>
  );
}

export function RunsPageHeadActions({
  onRefresh,
  onRequestSoc,
  onStartSafeRun,
  onStartScan,
  refreshBusy,
  safeRunBusy,
  safeRunDisabled
}: {
  onRefresh: () => void;
  onRequestSoc?: () => void;
  onStartSafeRun: () => void;
  onStartScan?: () => void;
  refreshBusy?: boolean;
  safeRunBusy?: boolean;
  safeRunDisabled?: boolean;
}) {
  const safeRunDisabledReason = safeRunDisabled
    ? 'Vector library launch is unavailable until a declared target group and customer-runnable bounded check are ready.'
    : '';
  return (
    <>
      {onRequestSoc ? <Button size="sm" variant="secondary" onClick={onRequestSoc}>Request SOC-gated run</Button> : null}
      <Button
        size="sm"
        loading={safeRunBusy}
        disabled={safeRunDisabled}
        title={safeRunDisabledReason || undefined}
        aria-describedby={safeRunDisabledReason ? 'safe-run-disabled-reason' : undefined}
        onClick={onStartSafeRun}
      >Open vector library</Button>
      {safeRunDisabledReason ? <span className="sr-only" id="safe-run-disabled-reason">{safeRunDisabledReason}</span> : null}
      {onStartScan ? <Button size="sm" onClick={onStartScan}>Start validation scan</Button> : null}
    </>
  );
}
