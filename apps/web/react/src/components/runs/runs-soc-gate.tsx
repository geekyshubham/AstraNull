import { useEffect, useMemo, useState, type FormEvent } from 'react';
import { Lock, ShieldCheck } from 'lucide-react';
import { Badge } from '../ui/badge';
import { AnchorButton, Button } from '../ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../ui/card';
import { Select, type SelectOption } from '../ui/select';
import { DataTable, type TableColumn } from '../ui/table';
import { ConfirmModal, formatMutationSuccessMessage, renderFriendlyEmptyState } from '../../lib/crud-ui';
import { PortalLoadingSkeleton } from '../../lib/empty-from-api';
import { GOVERNED_HIGH_SCALE_SCENARIOS, buildMetadataArtifactUploadBody } from '../../lib/high-scale';
import { sha256CanonicalJsonForCustody } from '../../lib/custody';
import { requestJson } from '../../lib/api';
import { apiErrorMessage } from '../../lib/error-messages';
import { buildDetailHref } from '../../lib/route-params';
import type { DataItem, PortalConfig, PortalData, Session } from '../../lib/types';
import { formatDate } from '../../lib/utils';

const HIGH_SCALE_SCENARIO_OPTIONS: SelectOption[] = GOVERNED_HIGH_SCALE_SCENARIOS.map((scenario) => ({
  value: scenario.id,
  label: `${scenario.label} (${scenario.id})`
}));

const HIGH_SCALE_CRITICALITY_OPTIONS: SelectOption[] = [
  { value: 'medium', label: 'Medium' },
  { value: 'high', label: 'High' },
  { value: 'critical', label: 'Critical' }
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

function SocQueueStat({ label, value }: { label: string; value: number }) {
  return (
    <div>
      <span className="muted">{label}</span>
      <strong className="tabular-nums">{value}</strong>
    </div>
  );
}

function stateBadgeTone(state: string): 'success' | 'warn' | 'info' | 'muted' {
  const normalized = state.trim().toLowerCase();
  if (normalized === 'scheduled') return 'info';
  if (['submitted', 'soc_review', 'under_review'].includes(normalized)) return 'warn';
  if (['closed', 'completed'].includes(normalized)) return 'success';
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
  const [internalRequestForm, setInternalRequestForm] = useState(false);
  const showRequestForm = requestFormOpen ?? internalRequestForm;
  const setShowRequestForm = onRequestFormOpenChange ?? setInternalRequestForm;
  const [packRequestId, setPackRequestId] = useState('');
  const [targetGroupId, setTargetGroupId] = useState(() => getString(data.targetGroups[0] ?? {}, ['id'], ''));
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
    const missingPack = items.filter((item) => getNestedString(item, ['authorization_pack_status', 'overall'], 'missing').toLowerCase() === 'missing').length;
    return { total: items.length, submitted, scheduled, missingPack };
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
  }, [config, session, data.highScale.length]);

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
    const form = new FormData(event.currentTarget);
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
        window_start: isoFromLocalDatetime(form.get('window_start')),
        window_end: isoFromLocalDatetime(form.get('window_end')),
        timezone: String(form.get('timezone') ?? 'UTC').trim() || 'UTC'
      },
      emergency_contacts: [{
        name: String(form.get('contact_name') ?? '').trim(),
        contact: String(form.get('contact') ?? '').trim()
      }],
      provider_context: {
        provider_name: String(form.get('provider_name') ?? '').trim(),
        requires_provider_approval: form.get('requires_provider_approval') === 'on'
      },
      scope_confirmation: true
    };
    const created = await runAction('create-high-scale', () => requestJson(config, session, '/v1/high-scale-requests', {
      method: 'POST',
      body
    }), 'SOC-gated request submitted for review.');
    if (created) {
      setShowRequestForm(false);
      event.currentTarget.reset();
    }
  }

  async function uploadPackArtifact(request: DataItem) {
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
    }), 'Authorization pack artifact uploaded (metadata-only).');
    setPackRequestId('');
  }

  const columns: TableColumn<DataItem>[] = [
    {
      key: 'request',
      label: 'Request',
      render: (item) => {
        const requestId = getString(item, ['id'], '');
        // §4.7: customers see their own high-scale requests INLINE (all state is in this row);
        // the queue-detail SOC workspace is staff-only, so customers do NOT navigate there
        // (avoids the staff-gated "access denied" dead-end). Staff open the workspace from here.
        if (!isStaffPrincipal) {
          return <code title={`High-scale request ${requestId} · status shown inline`}>{requestId}</code>;
        }
        return (
          <AnchorButton
            variant="ghost"
            href={buildDetailHref('queue-detail', requestId)}
            aria-label={`Open SOC workspace for request ${requestId}`}
          >
            <code>{getString(item, ['id'])}</code>
          </AnchorButton>
        );
      }
    },
    { key: 'policy', label: 'Policy', render: (item) => <code>{getString(item, ['policy_id', 'requested_scenario_families'], 'soc_gated')}</code> },
    { key: 'group', label: 'Target group', render: (item) => targetGroupDisplayName(data, getString(item, ['target_group_id'])) },
    { key: 'limits', label: 'Governed limits', render: (item) => governedLimitDisplay(item) },
    {
      key: 'pack',
      label: 'Pack',
      render: (item) => {
        const overall = getNestedString(item, ['authorization_pack_status', 'overall'], 'missing');
        return <Badge tone={packBadgeTone(overall)} title={`Pack status from authorization_pack_status.overall: ${overall}`}>{overall}</Badge>;
      }
    },
    {
      key: 'state',
      label: 'State',
      render: (item) => {
        const state = getString(item, ['state']);
        return <Badge tone={stateBadgeTone(state)} title={`Request state from API: ${state}`}>{state}</Badge>;
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
        if (pack === 'missing' || pack === 'incomplete' || pack === 'partial') {
          return (
            <AnchorButton
              size="sm"
              variant="ghost"
              href={buildDetailHref('queue-detail', id)}
              aria-label={`Complete authorization pack for request ${id}`}
            >
              Complete pack
            </AnchorButton>
          );
        }
        return <span className="muted mono">awaiting SOC</span>;
      }
    }
  ];

  return (
    <>
      <Card className="runs-soc-gate">
        <CardHeader>
          <CardTitle>SOC-gated queue</CardTitle>
          <CardDescription>High-scale policies cannot execute directly. SOC schedules and executes under kill switch governance.</CardDescription>
        </CardHeader>
        <CardContent className="stack-tight">
          <div className="callout callout-soc" role="note" aria-labelledby="soc-gate-callout-title">
            <div className="callout-icon" aria-hidden="true">
              <Lock size={18} />
            </div>
            <div className="callout-body">
              <div className="callout-title" id="soc-gate-callout-title">SOC gates every high-scale run</div>
              <p className="callout-desc">
                Selecting an SOC-gated policy submits an approval request instead of executing.
                The SOC accepts the authorization pack, arms the kill switch, and executes on a scheduled window.
                Customers never generate high-volume load directly.
              </p>
            </div>
          </div>
          <div className="soc-queue-summary" aria-label="SOC queue summary">
            <SocQueueStat label="In review" value={summary.submitted} />
            <SocQueueStat label="Scheduled" value={summary.scheduled} />
            <SocQueueStat label="Pack missing" value={summary.missingPack} />
          </div>
          {queueLoading ? <PortalLoadingSkeleton rows={2} /> : null}
          {queueError ? <div className="form-banner error">{queueError}</div> : null}
          {!queueLoading && !queueError ? (
            <DataTable
              columns={columns}
              items={queue ?? []}
              empty={renderFriendlyEmptyState({
                icon: ShieldCheck,
                title: 'No SOC-gated requests in queue.',
                body: 'Submit a governed request when you need high-scale validation under SOC oversight.',
                actionLabel: 'Request SOC-gated run',
                onAction: () => setShowRequestForm(true)
              })}
            />
          ) : null}
        </CardContent>
      </Card>

      {showRequestForm ? (
        <Card>
          <CardHeader>
            <CardTitle>Request SOC-gated run</CardTitle>
            <CardDescription>Submit authorization metadata for SOC review. Execution remains staff-only on the SOC console.</CardDescription>
          </CardHeader>
          <CardContent>
            <form className="product-form" onSubmit={handleCreateRequest} aria-busy={busy === 'create-high-scale' || undefined}>
              <input type="hidden" name="target_group_id" value={targetGroupId} />
              <Select label="Target group" value={targetGroupId} options={targetGroupOptions} disabled={data.targetGroups.length === 0 || busy !== ''} onChange={setTargetGroupId} />
              <label className="full"><span>Objective</span><textarea name="objective" rows={3} required disabled={busy !== ''} placeholder="Describe the governed validation objective." /></label>
              <Select label="Business criticality" name="business_criticality" value={criticality} options={HIGH_SCALE_CRITICALITY_OPTIONS} onChange={setCriticality} disabled={busy !== ''} />
              <label><span>Window start</span><input name="window_start" type="datetime-local" defaultValue={datetimeLocalValue(24)} required disabled={busy !== ''} /></label>
              <label><span>Window end</span><input name="window_end" type="datetime-local" defaultValue={datetimeLocalValue(48)} required disabled={busy !== ''} /></label>
              <Select
                label="Governed scenario family"
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
                  />
                </label>
              ) : null}
              <label><span>Maximum duration (minutes)</span><input name="max_duration_minutes" type="number" min={1} max={720} step={1} defaultValue={45} required disabled={busy !== ''} /></label>
              <label><span>Provider</span><input name="provider_name" placeholder="CDN or WAF provider fronting this scope" required disabled={busy !== ''} /></label>
              <label><span>Emergency contact</span><input name="contact_name" placeholder="Name of the on-call owner SOC can reach" required disabled={busy !== ''} /></label>
              <label><span>Contact path</span><input name="contact" placeholder="Email or phone SOC can reach during the window" required disabled={busy !== ''} /></label>
              <label className="check-row full"><input name="scope_confirmation" type="checkbox" disabled={busy !== ''} /><span>I confirm declared scope and authorization metadata are accurate.</span></label>
              <div className="form-actions full">
                <Button type="submit" loading={busy === 'create-high-scale'} disabled={busy !== '' || data.targetGroups.length === 0}>Submit request</Button>
                <Button type="button" variant="ghost" disabled={busy !== ''} onClick={() => setShowRequestForm(false)}>Cancel</Button>
              </div>
            </form>
          </CardContent>
        </Card>
      ) : null}

      <ConfirmModal
        open={Boolean(packRequestId)}
        title="Complete authorization pack"
        description={(
          <>
            <p>Upload metadata-only authorization pack artifacts for request <code>{packRequestId}</code>.</p>
            <p className="muted">Are you sure? This writes an audit entry and submits pack metadata for SOC review.</p>
          </>
        )}
        confirmLabel="Upload pack metadata"
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
  refreshBusy,
  safeRunBusy,
  safeRunDisabled
}: {
  onRefresh: () => void;
  onRequestSoc: () => void;
  onStartSafeRun: () => void;
  refreshBusy?: boolean;
  safeRunBusy?: boolean;
  safeRunDisabled?: boolean;
}) {
  return (
    <>
      <Button size="sm" variant="secondary" onClick={onRequestSoc}>Request SOC-gated run</Button>
      <Button size="sm" loading={safeRunBusy} disabled={safeRunDisabled} onClick={onStartSafeRun}>Run checks</Button>
    </>
  );
}