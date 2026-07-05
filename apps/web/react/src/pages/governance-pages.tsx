import { useEffect, useMemo, useState, type FormEvent } from 'react';
import { Bell, ClipboardList, FileCheck2, FileText, ShieldCheck, Siren } from 'lucide-react';
import { Badge } from '../components/ui/badge';
import { Button } from '../components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../components/ui/card';
import { EmptyState } from '../components/ui/empty-state';
import { DataTable, type TableColumn } from '../components/ui/table';
import { isStaffSocRole, requestJson, requestSocJson } from '../lib/api';
import { socDevScheduleWindow } from '../lib/high-scale';
import {
  computeReleaseEvidenceCoverage,
  pickReleaseEvidenceCustodyUri,
  summarizeReleaseEvidenceValidation
} from '../lib/release-evidence';
import type { DataItem, PortalConfig, PortalData, Session } from '../lib/types';
import { formatDate } from '../lib/utils';
import { MetricCard, PageHeader } from './page-components';

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
  'agent.offline',
  'safe_test.completed',
  'high_scale.state_change',
  'report.ready',
  'bootstrap_token.created',
  'bootstrap_token.revoked'
] as const;

function canWriteNotifications(role: string | undefined) {
  return role === 'admin' || role === 'owner';
}

function canReadAudit(role: string | undefined) {
  return ['admin', 'owner', 'soc', 'auditor'].includes(String(role ?? ''));
}

function canReadReleaseEvidence(role: string | undefined) {
  return ['admin', 'owner', 'soc', 'auditor'].includes(String(role ?? ''));
}

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
  const [busy, setBusy] = useState('');
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');
  const canWrite = canWriteNotifications(session.role);
  const attempts = useMemo(() => deliveryAttempts(data.notificationEvents), [data.notificationEvents]);
  const retryItems = attempts.filter((item) => getString(item, ['status']) === 'provider_retry_scheduled');
  const dlqItems = attempts.filter((item) => getString(item, ['status']) === 'provider_failed_dlq');

  const ruleColumns: TableColumn<DataItem>[] = [
    { key: 'channel', label: 'Channel', render: (item) => <Badge tone="info">{getString(item, ['channel'])}</Badge> },
    { key: 'enabled', label: 'Enabled', render: (item) => item.enabled === false ? 'disabled' : 'enabled' },
    { key: 'triggers', label: 'Triggers', render: (item) => (Array.isArray(item.triggers) ? item.triggers.length : 0) },
    { key: 'destination', label: 'Destination', render: (item) => getString(item, ['destination_preview'], 'metadata-only') }
  ];
  const eventColumns: TableColumn<DataItem>[] = [
    { key: 'trigger', label: 'Trigger', render: (item) => getString(item, ['trigger']) },
    { key: 'subject', label: 'Subject', render: (item) => getString(item, ['subject']) },
    { key: 'created', label: 'Created', render: (item) => formatDate(item.created_at) }
  ];

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
      const payload = (err as Error & { payload?: unknown }).payload as { error?: string; message?: string } | undefined;
      setError(payload?.message ?? payload?.error ?? (err instanceof Error ? err.message : 'Notification action failed.'));
      return null;
    } finally {
      setBusy('');
    }
  }

  function resolveNotificationDestination(channel: string, rawDestination: string) {
    const preview = rawDestination.trim();
    if (channel === 'webhook') {
      if (/^https?:\/\//i.test(preview)) return preview;
      return 'https://hooks.example.invalid/notifications';
    }
    if (channel === 'email') {
      return preview.includes('@') ? preview : 'alerts@example.invalid';
    }
    return preview || `${channel}-destination.example.invalid`;
  }

  async function handleCreateRule(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const formEl = event.currentTarget;
    const form = new FormData(formEl);
    const channel = String(form.get('channel') ?? 'webhook').trim();
    const trigger = String(form.get('trigger') ?? 'finding.high_severity').trim();
    const destination = resolveNotificationDestination(
      channel,
      String(form.get('destination_preview') ?? '').trim()
    );
    await runAction('create-notification-rule', () => requestJson(config, session, '/v1/notifications', {
      method: 'POST',
      body: {
        channel,
        enabled: true,
        triggers: [trigger],
        destination
      }
    }), 'Notification rule created (metadata-only delivery ledger).');
    formEl.reset();
  }

  async function processRetries(dryRun: boolean) {
    await runAction(`process-retries-${dryRun ? 'preview' : 'run'}`, () => requestJson(config, session, '/v1/notifications/retries/process', {
      method: 'POST',
      body: { dry_run: dryRun }
    }), dryRun ? 'Due retry preview completed.' : 'Due retries processed (metadata-only).');
  }

  async function redriveDlq(dryRun: boolean) {
    const attemptIds = dlqItems
      .map((item) => getString(item, ['id', 'attempt_id'], ''))
      .filter(Boolean);
    await runAction(`redrive-dlq-${dryRun ? 'preview' : 'run'}`, () => requestJson(config, session, '/v1/notifications/dlq/redrive', {
      method: 'POST',
      body: {
        dry_run: dryRun,
        attempt_ids: attemptIds.length > 0 ? attemptIds : undefined
      }
    }), dryRun ? 'DLQ redrive preview completed.' : 'DLQ attempts requeued (metadata-only).');
  }

  return (
    <div className="content">
      <PageHeader route="notifications" />
      <div className="metric-grid three">
        <MetricCard label="Rules" value={data.notificationRules.length} sub="Tenant notification rules" icon={Bell} tone="info" />
        <MetricCard label="Events" value={data.notificationEvents.length} sub="Recent emitted events" icon={ClipboardList} tone="success" />
        <MetricCard label="DLQ" value={dlqItems.length} sub={`${retryItems.length} retry scheduled`} icon={Siren} tone={dlqItems.length > 0 ? 'warn' : 'success'} />
      </div>
      {(message || error) && <div className={error ? 'form-banner error' : 'form-banner'}>{error || message}</div>}
      {canWrite ? (
        <Card>
          <CardHeader>
            <CardTitle>Create notification rule</CardTitle>
            <CardDescription>Metadata-only rule creation. External delivery remains opt-in through server delivery mode.</CardDescription>
          </CardHeader>
          <CardContent>
            <form className="product-form" onSubmit={handleCreateRule}>
              <label><span>Channel</span><select name="channel" defaultValue="webhook"><option value="webhook">webhook</option><option value="email">email</option><option value="slack">slack</option><option value="teams">teams</option><option value="in_app">in_app</option></select></label>
              <label><span>Trigger</span>
                <select name="trigger" defaultValue="finding.high_severity">
                  {NOTIFICATION_TRIGGERS.map((trigger) => <option key={trigger} value={trigger}>{trigger}</option>)}
                </select>
              </label>
              <label className="full"><span>Destination</span><input name="destination_preview" placeholder="https://hooks.example.invalid/notifications" /></label>
              <div className="form-actions full"><Button type="submit" disabled={busy !== ''}>Add rule</Button></div>
            </form>
          </CardContent>
        </Card>
      ) : (
        <Card><CardContent><p className="muted">Notification write access requires owner or admin role.</p></CardContent></Card>
      )}
      <div className="split">
        <Card>
          <CardHeader><CardTitle>Rules</CardTitle></CardHeader>
          <CardContent>
            <DataTable columns={ruleColumns} items={data.notificationRules} empty={<EmptyState icon={Bell} title="No notification rules." body="Create a metadata-only rule to start recording delivery intent." />} />
          </CardContent>
        </Card>
        <Card>
          <CardHeader><CardTitle>Recent events</CardTitle></CardHeader>
          <CardContent>
            <DataTable columns={eventColumns} items={data.notificationEvents.slice().reverse()} empty={<EmptyState icon={ClipboardList} title="No notification events." body="Events appear after configured triggers fire." />} />
          </CardContent>
        </Card>
      </div>
      <Card>
        <CardHeader>
          <CardTitle>Delivery operations</CardTitle>
          <CardDescription>Retry and DLQ controls are metadata-only in developer validation.</CardDescription>
        </CardHeader>
        <CardContent className="row-actions">
          <Button size="sm" variant="secondary" disabled={!canWrite || busy !== ''} onClick={() => void processRetries(true)}>Preview due retries</Button>
          <Button size="sm" disabled={!canWrite || busy !== ''} onClick={() => void processRetries(false)}>Process due retries</Button>
          <Button size="sm" variant="ghost" disabled={!canWrite || busy !== '' || dlqItems.length === 0} onClick={() => void redriveDlq(true)}>Preview DLQ redrive</Button>
          <Button size="sm" variant="secondary" disabled={!canWrite || busy !== '' || dlqItems.length === 0} onClick={() => void redriveDlq(false)}>Redrive DLQ</Button>
        </CardContent>
      </Card>
    </div>
  );
}

export function AuditPage({ data, session }: { data: PortalData; session: Session }) {
  const [filter, setFilter] = useState('');
  const [custodyOnly, setCustodyOnly] = useState(false);
  const [selectedId, setSelectedId] = useState('');
  const allowed = canReadAudit(session.role);
  const items = data.audit.filter((entry) => {
    const action = getString(entry, ['action'], '').toLowerCase();
    if (custodyOnly && !action.includes('custody') && !action.includes('export') && !action.includes('report')) {
      return false;
    }
    if (!filter.trim()) return true;
    const haystack = `${getString(entry, ['action'])} ${getString(entry, ['resource_type'])} ${getString(entry, ['resource_id'])}`.toLowerCase();
    return haystack.includes(filter.trim().toLowerCase());
  });
  const selectedEntry = items.find((entry) => getString(entry, ['id', 'audit_id'], '') === selectedId) ?? null;
  const columns: TableColumn<DataItem>[] = [
    { key: 'time', label: 'Time', render: (item) => formatDate(item.timestamp ?? item.created_at) },
    { key: 'action', label: 'Action', render: (item) => getString(item, ['action']) },
    { key: 'resource', label: 'Resource', render: (item) => `${getString(item, ['resource_type'], '')} ${getString(item, ['resource_id'], '')}`.trim() },
    { key: 'actor', label: 'Actor', render: (item) => getString(item, ['actor_role', 'actor_user_id'], 'system') },
    {
      key: 'inspect',
      label: 'Inspect',
      render: (item) => {
        const id = getString(item, ['id', 'audit_id'], getString(item, ['created_at'], ''));
        return <Button size="sm" variant={id === selectedId ? 'default' : 'secondary'} onClick={() => setSelectedId(id)}>Open</Button>;
      }
    }
  ];

  return (
    <div className="content">
      <PageHeader route="audit" />
      {!allowed ? (
        <EmptyState icon={ClipboardList} title="Audit access required." body="Switch to owner, admin, SOC, or auditor role to read the tenant audit log." />
      ) : (
        <>
          <Card>
            <CardHeader>
              <CardTitle>Audit log</CardTitle>
              <CardDescription>Security-relevant tenant actions with hash-chain integrity on the backend.</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="product-form">
                <label className="full"><span>Filter</span><input value={filter} onChange={(event) => setFilter(event.target.value)} placeholder="action, resource type, or id" /></label>
                <label><span>Custody chain only</span><input type="checkbox" checked={custodyOnly} onChange={(event) => setCustodyOnly(event.target.checked)} /></label>
              </div>
              <DataTable columns={columns} items={items.slice().reverse()} empty={<EmptyState icon={ClipboardList} title="No audit entries." body="Security-relevant actions will appear here after workflow activity." />} />
            </CardContent>
          </Card>
          {selectedEntry ? (
            <Card>
              <CardHeader>
                <CardTitle>Custody and metadata drilldown</CardTitle>
                <CardDescription>{getString(selectedEntry, ['action'])} · {getString(selectedEntry, ['resource_type'])}</CardDescription>
              </CardHeader>
              <CardContent className="kv-list">
                <div><span>Actor</span><strong>{getString(selectedEntry, ['actor_user_id'])} ({getString(selectedEntry, ['actor_role'])})</strong></div>
                <div><span>Resource</span><strong>{getString(selectedEntry, ['resource_id'])}</strong></div>
                <div><span>Timestamp</span><strong>{formatDate(selectedEntry.timestamp ?? selectedEntry.created_at)}</strong></div>
                <div><span>Metadata keys</span><strong>{Object.keys((selectedEntry.metadata as object) ?? {}).join(', ') || 'none'}</strong></div>
                {selectedEntry.metadata && typeof selectedEntry.metadata === 'object' ? (
                  <pre className="codeblock">{JSON.stringify(selectedEntry.metadata, null, 2).slice(0, 1800)}</pre>
                ) : null}
              </CardContent>
            </Card>
          ) : null}
        </>
      )}
    </div>
  );
}

export function ReleaseEvidencePage({ data, session }: { data: PortalData; session: Session }) {
  const allowed = canReadReleaseEvidence(session.role);
  const attestation = data.releaseAttestation;
  const coverage = computeReleaseEvidenceCoverage(data.releaseEvidence);
  const columns: TableColumn<DataItem>[] = [
    { key: 'kind', label: 'Kind', render: (item) => <Badge tone="info">{getString(item, ['kind'])}</Badge> },
    { key: 'status', label: 'Status', render: (item) => getString(item, ['status', 'validation_status'], 'recorded') },
    { key: 'validation', label: 'Validation', render: (item) => summarizeReleaseEvidenceValidation(getNestedItem(item, ['validation']) ?? (item.validation as DataItem | undefined) ?? null) },
    { key: 'release', label: 'Release', render: (item) => getString(item, ['release_id', 'id']) },
    { key: 'custody', label: 'Custody', render: (item) => {
      const uri = pickReleaseEvidenceCustodyUri(getNestedItem(item, ['evidence']) ?? (item.evidence as DataItem | undefined));
      return uri ? uri.slice(0, 48) + (uri.length > 48 ? '…' : '') : 'metadata-only';
    } },
    { key: 'created', label: 'Created', render: (item) => formatDate(item.created_at) }
  ];

  function exportGapLedger() {
    const payload = {
      exported_at: new Date().toISOString(),
      tenant_id: session.tenant_id ?? 'ten_demo',
      coverage,
      attestation,
      records: data.releaseEvidence.map((item) => ({
        kind: getString(item, ['kind']),
        status: getString(item, ['status']),
        validation: summarizeReleaseEvidenceValidation(getNestedItem(item, ['validation']) ?? (item.validation as DataItem | undefined) ?? null),
        custody_uri: pickReleaseEvidenceCustodyUri(getNestedItem(item, ['evidence']) ?? (item.evidence as DataItem | undefined))
      }))
    };
    void navigator.clipboard.writeText(JSON.stringify(payload, null, 2));
  }

  return (
    <div className="content">
      <PageHeader route="release-evidence" />
      {!allowed ? (
        <EmptyState icon={FileText} title="Release evidence access required." body="Switch to owner, admin, SOC, or auditor role to inspect production release evidence." />
      ) : (
        <>
          <div className="metric-grid three">
            <MetricCard label="Evidence kinds" value={`${coverage.recorded}/${coverage.expected}`} sub={coverage.kindsComplete ? 'Inventory complete' : `${coverage.missing.length} kinds missing`} icon={FileText} tone={coverage.kindsComplete ? 'success' : 'warn'} />
            <MetricCard label="Attestation" value={getNestedString(attestation, ['signoff_status'], 'unknown')} sub="Staging readiness attestation" icon={ShieldCheck} tone="success" />
            <MetricCard label="Production ready" value={String(attestation?.production_ready ?? 'unknown')} sub="Metadata-only release gate snapshot" icon={FileCheck2} tone="muted" />
          </div>
          <Card>
            <CardHeader>
              <CardTitle>Gap ledger</CardTitle>
              <CardDescription>Kinds not yet attached to accepted release evidence for this tenant.</CardDescription>
            </CardHeader>
            <CardContent className="product-form">
              <p className="muted">Recorded {coverage.recorded} of {coverage.expected} required kinds. Customer launch remains gated by staging, legal, SOC, and security signoffs.</p>
              {coverage.missing.length > 0 ? (
                <div className="queue-list">
                  {coverage.missing.slice(0, 12).map((kind) => <div key={kind}><Badge tone="warn">{kind}</Badge></div>)}
                  {coverage.missing.length > 12 ? <p className="muted">…and {coverage.missing.length - 12} more kinds.</p> : null}
                </div>
              ) : <p className="muted">All required kinds are recorded for this tenant inventory snapshot.</p>}
              <Button size="sm" variant="secondary" onClick={exportGapLedger}>Copy gap ledger JSON</Button>
            </CardContent>
          </Card>
          <Card>
            <CardHeader>
              <CardTitle>Release evidence inventory</CardTitle>
              <CardDescription>Accepted kinds, validation summary, and custody URI previews without raw bodies.</CardDescription>
            </CardHeader>
            <CardContent>
              <DataTable columns={columns} items={data.releaseEvidence} empty={<EmptyState icon={FileText} title="No release evidence records." body="Operator evidence validators populate this inventory during release rehearsals." />} />
            </CardContent>
          </Card>
          {attestation && (
            <Card>
              <CardHeader>
                <CardTitle>Attestation snapshot</CardTitle>
                <CardDescription>From `/v1/production-release-evidence/attestation`.</CardDescription>
              </CardHeader>
              <CardContent className="kv-list">
                <div><span>Signoff status</span><strong>{getNestedString(attestation, ['signoff_status'])}</strong></div>
                <div><span>Production ready</span><strong>{String(attestation.production_ready ?? 'unknown')}</strong></div>
                <div><span>Profile</span><strong>{getNestedString(attestation, ['profile'], 'full')}</strong></div>
                <div><span>Checked at</span><strong>{formatDate(attestation.checked_at ?? attestation.created_at)}</strong></div>
              </CardContent>
            </Card>
          )}
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
  staffSocSurface = false
}: {
  data: PortalData;
  config: PortalConfig;
  session: Session;
  onRefresh: () => Promise<void>;
  staffSocSurface?: boolean;
}) {
  const [busy, setBusy] = useState('');
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');
  const [output, setOutput] = useState('');
  const [selectedRequestId, setSelectedRequestId] = useState(() => getString(data.highScale[0] ?? {}, ['id'], ''));
  const [adapterStatus, setAdapterStatus] = useState<DataItem | null>(null);
  const [postTestReport, setPostTestReport] = useState<DataItem | null>(null);
  const isSoc = staffSocSurface
    ? session.principal === 'staff' && isStaffSocRole(session)
    : session.role === 'soc' && session.principal !== 'staff';

  async function socRequest(path: string, options: { method?: string; body?: unknown } = {}) {
    if (staffSocSurface) return requestSocJson(config, session, path, options);
    return requestJson(config, session, path, options);
  }
  const activeRequest = data.highScale.find((item) => getString(item, ['id'], '') === selectedRequestId) ?? data.highScale[0] ?? null;
  const artifacts = Array.isArray(activeRequest?.artifacts) ? activeRequest.artifacts as DataItem[] : [];

  useEffect(() => {
    if (data.highScale.length === 0) {
      if (selectedRequestId) setSelectedRequestId('');
      return;
    }
    const selectedStillExists = data.highScale.some((item) => getString(item, ['id'], '') === selectedRequestId);
    if (!selectedStillExists) setSelectedRequestId(getString(data.highScale[0] ?? {}, ['id'], ''));
  }, [data.highScale, selectedRequestId]);

  const requestColumns: TableColumn<DataItem>[] = [
    { key: 'id', label: 'Request', render: (item) => getString(item, ['id']) },
    { key: 'state', label: 'State', render: (item) => <Badge tone="warn">{getString(item, ['state'])}</Badge> },
    { key: 'target', label: 'Target group', render: (item) => getString(item, ['target_group_id']) },
    { key: 'pack', label: 'Pack', render: (item) => getNestedString(item, ['authorization_pack_status', 'overall'], 'missing') },
    {
      key: 'actions',
      label: 'Actions',
      render: (item) => {
        const id = getString(item, ['id'], '');
        const state = getString(item, ['state'], '');
        const packReady = getNestedString(item, ['authorization_pack_status', 'overall'], '') === 'accepted';
        return (
          <div className="row-actions">
            <Button size="sm" variant={id === selectedRequestId ? 'default' : 'secondary'} onClick={() => setSelectedRequestId(id)}>Select</Button>
            {['submitted', 'under_review'].includes(state) && packReady ? <Button size="sm" variant="secondary" disabled={busy !== ''} onClick={() => void socAction(id, 'approve')}>Approve</Button> : null}
            {state === 'approved' ? <Button size="sm" variant="secondary" disabled={busy !== ''} onClick={() => void socAction(id, 'schedule', socDevScheduleWindow())}>Schedule</Button> : null}
            {state === 'scheduled' ? <Button size="sm" variant="secondary" disabled={busy !== ''} onClick={() => void socAction(id, 'start')}>Start</Button> : null}
            {state === 'running' ? <Button size="sm" variant="secondary" disabled={busy !== ''} onClick={() => void socAction(id, 'stop')}>Stop</Button> : null}
            {state === 'stopped' ? <Button size="sm" variant="secondary" disabled={busy !== ''} onClick={() => void socAction(id, 'close')}>Close</Button> : null}
          </div>
        );
      }
    }
  ];

  const artifactColumns: TableColumn<DataItem>[] = [
    { key: 'type', label: 'Type', render: (item) => getString(item, ['type']) },
    { key: 'status', label: 'Status', render: (item) => <Badge tone={getString(item, ['status']) === 'accepted' ? 'success' : 'warn'}>{getString(item, ['status'])}</Badge> },
    { key: 'digest', label: 'SHA-256', render: (item) => getString(item, ['content_sha256'], '—').slice(0, 16) },
    {
      key: 'actions',
      label: 'Review',
      render: (item) => {
        const artifactId = getString(item, ['id'], '');
        return (
          <div className="row-actions">
            <Button size="sm" variant="secondary" disabled={busy !== '' || !selectedRequestId} onClick={() => void reviewArtifact(selectedRequestId, artifactId, 'accepted')}>Accept</Button>
            <Button size="sm" variant="ghost" disabled={busy !== '' || !selectedRequestId} onClick={() => void reviewArtifact(selectedRequestId, artifactId, 'rejected')}>Reject</Button>
          </div>
        );
      }
    }
  ];

  async function socAction(requestId: string, action: string, body: Record<string, unknown> = {}) {
    if (!requestId) return null;
    setBusy(`${action}-${requestId}`);
    setError('');
    setMessage('');
    try {
      const payload = await socRequest(`/internal/soc/high-scale/${encodeURIComponent(requestId)}/${action}`, {
        method: 'POST',
        body
      });
      setOutput(JSON.stringify(payload, null, 2));
      setMessage(`SOC ${action} completed for ${requestId}.`);
      await onRefresh();
      return payload;
    } catch (err) {
      const payload = (err as Error & { payload?: unknown }).payload as { error?: string; message?: string } | undefined;
      setError(payload?.message ?? payload?.error ?? (err instanceof Error ? err.message : 'SOC action failed.'));
      return null;
    } finally {
      setBusy('');
    }
  }

  async function reviewArtifact(requestId: string, artifactId: string, status: 'accepted' | 'rejected') {
    if (!requestId || !artifactId) return;
    await socAction(requestId, `artifacts/${artifactId}/review`, { status, notes: `SOC ${status} via console` });
  }

  async function loadAdapterStatus(requestId: string) {
    if (!requestId) return;
    setBusy(`adapter-${requestId}`);
    setError('');
    try {
      const payload = await socRequest(`/internal/soc/high-scale/${encodeURIComponent(requestId)}/adapter-status`);
      setAdapterStatus(payload as DataItem);
      setOutput(JSON.stringify(payload, null, 2));
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Adapter status unavailable.');
      setAdapterStatus(null);
    } finally {
      setBusy('');
    }
  }

  async function submitSocNote(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!selectedRequestId) return;
    const body = String(new FormData(event.currentTarget).get('body') ?? '').trim();
    await socAction(selectedRequestId, 'notes', { body });
    event.currentTarget.reset();
  }

  async function submitPostTestReport(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!selectedRequestId) return;
    const form = new FormData(event.currentTarget);
    const payload = await socAction(selectedRequestId, 'post-test-report', {
      impact_summary: String(form.get('impact_summary') ?? '').trim(),
      recommendations: String(form.get('recommendations') ?? '').trim(),
      residual_risk: String(form.get('residual_risk') ?? '').trim()
    });
    if (payload) setPostTestReport(payload as DataItem);
  }

  async function setKillSwitch(active: boolean) {
    setBusy(active ? 'kill-on' : 'kill-off');
    setError('');
    setMessage('');
    try {
      const payload = await socRequest('/internal/soc/kill-switch', {
        method: 'POST',
        body: { active, reason: active ? 'SOC console activation' : 'SOC console cleared' }
      });
      setOutput(JSON.stringify(payload, null, 2));
      setMessage(active ? 'Kill switch activated.' : 'Kill switch cleared.');
      await onRefresh();
    } catch (err) {
      const payload = (err as Error & { payload?: unknown }).payload as { error?: string; message?: string } | undefined;
      setError(payload?.message ?? payload?.error ?? (err instanceof Error ? err.message : 'Kill switch action failed.'));
    } finally {
      setBusy('');
    }
  }

  if (!isSoc) {
    const killSwitchActive = Boolean(data.state?.kill_switch?.active ?? data.state?.kill_switch?.enabled);
    return (
      <div className="content">
        <PageHeader route={staffSocSurface ? 'internal-soc' : 'soc'} />
        <EmptyState
          icon={ShieldCheck}
          title={staffSocSurface ? 'Staff SOC role required.' : 'SOC role required.'}
          body={staffSocSurface
            ? 'Sign in with a staff soc_analyst or soc_lead role to use the governed high-scale execution console.'
            : 'Switch the workspace role to soc to use the governed high-scale execution console.'}
        />
        <Card>
          <CardHeader>
            <CardTitle>Kill switch</CardTitle>
            <CardDescription>Read-only tenant emergency-stop status. Activation and clearance require an SOC role.</CardDescription>
          </CardHeader>
          <CardContent className="kv-list">
            <div><span>Status</span><strong>{killSwitchActive ? 'Active' : 'Inactive'}</strong></div>
            <div><span>Reason</span><strong>{getString(data.state?.kill_switch as DataItem, ['reason'], 'tenant-scoped emergency stop')}</strong></div>
          </CardContent>
        </Card>
      </div>
    );
  }

  return (
    <div className="content">
      <PageHeader route={staffSocSurface ? 'internal-soc' : 'soc'} eyebrow="SOC execution plane" />
      <div className="metric-grid three">
        <MetricCard label="Queue" value={data.highScale.length} sub="Governed high-scale requests" icon={Siren} tone="warn" />
        <MetricCard label="Kill switch" value={(data.state?.kill_switch?.active ?? data.state?.kill_switch?.enabled) ? 'ON' : 'OFF'} sub={getString(data.state?.kill_switch as DataItem, ['reason'], 'tenant-scoped emergency stop')} icon={ShieldCheck} tone={(data.state?.kill_switch?.active ?? data.state?.kill_switch?.enabled) ? 'danger' : 'success'} />
        <MetricCard label="Open findings" value={data.state?.open_findings ?? data.findings.length} sub="Customer posture while tests run" icon={FileCheck2} tone="info" />
      </div>
      {(message || error) && <div className={error ? 'form-banner error' : 'form-banner'}>{error || message}</div>}
      <Card>
        <CardHeader>
          <CardTitle>Kill switch</CardTitle>
          <CardDescription>Tenant-scoped emergency stop for governed high-scale adapter runs.</CardDescription>
        </CardHeader>
        <CardContent className="row-actions">
          <Button size="sm" variant="danger" disabled={busy !== ''} onClick={() => void setKillSwitch(true)}>Activate</Button>
          <Button size="sm" variant="secondary" disabled={busy !== ''} onClick={() => void setKillSwitch(false)}>Clear</Button>
        </CardContent>
      </Card>
      <Card>
        <CardHeader>
          <CardTitle>High-scale queue</CardTitle>
          <CardDescription>SOC-only lifecycle actions call `/internal/soc/high-scale/*` routes.</CardDescription>
        </CardHeader>
        <CardContent>
          <DataTable columns={requestColumns} items={data.highScale} empty={<EmptyState icon={ShieldCheck} title="No high-scale requests." body="Customer requests appear here after intake and authorization-pack review." />} />
        </CardContent>
      </Card>
      {activeRequest ? (
        <div className="split">
          <Card>
            <CardHeader>
              <CardTitle>Authorization artifacts</CardTitle>
              <CardDescription>Review metadata-only artifacts for {getString(activeRequest, ['id'])}.</CardDescription>
            </CardHeader>
            <CardContent>
              <DataTable columns={artifactColumns} items={artifacts} empty={<EmptyState icon={FileCheck2} title="No artifacts uploaded." body="Customer authorization pack artifacts appear after metadata-only upload." />} />
            </CardContent>
          </Card>
          <Card>
            <CardHeader>
              <CardTitle>Adapter status</CardTitle>
              <CardDescription>{'Governed adapter dry-run telemetry from `/internal/soc/high-scale/:id/adapter-status`.'}</CardDescription>
            </CardHeader>
            <CardContent className="product-form">
              <Button size="sm" variant="secondary" disabled={busy !== ''} onClick={() => void loadAdapterStatus(selectedRequestId)}>Refresh adapter status</Button>
              {adapterStatus ? (
                <div className="kv-list">
                  <div><span>State</span><strong>{getNestedString(adapterStatus, ['adapter', 'state'], getString(adapterStatus, ['state']))}</strong></div>
                  <div><span>Traffic generated</span><strong>{String(getNestedString(adapterStatus, ['adapter', 'traffic_generated'], 'false'))}</strong></div>
                  <div><span>Last updated</span><strong>{formatDate(adapterStatus.updated_at ?? adapterStatus.checked_at)}</strong></div>
                </div>
              ) : <p className="muted">Adapter status not loaded yet.</p>}
            </CardContent>
          </Card>
        </div>
      ) : null}
      {activeRequest ? (
        <div className="split">
          <Card>
            <CardHeader>
              <CardTitle>SOC notes</CardTitle>
              <CardDescription>Metadata-only notes are redacted before persistence.</CardDescription>
            </CardHeader>
            <CardContent>
              <form className="product-form" onSubmit={submitSocNote}>
                <label className="full"><span>Note</span><textarea name="body" rows={4} placeholder="Execution observation or coordination note" required /></label>
                <div className="form-actions full"><Button type="submit" disabled={busy !== ''}>Add SOC note</Button></div>
              </form>
            </CardContent>
          </Card>
          <Card>
            <CardHeader>
              <CardTitle>Post-test report</CardTitle>
              <CardDescription>Required before close when request is stopped.</CardDescription>
            </CardHeader>
            <CardContent>
              <form className="product-form" onSubmit={submitPostTestReport}>
                <label className="full"><span>Impact summary</span><textarea name="impact_summary" rows={3} required /></label>
                <label className="full"><span>Recommendations</span><textarea name="recommendations" rows={3} /></label>
                <label><span>Residual risk</span><input name="residual_risk" defaultValue="low" /></label>
                <div className="form-actions full"><Button type="submit" disabled={busy !== ''}>Save post-test report</Button></div>
              </form>
              {postTestReport ? <p className="muted">Report {getString(postTestReport, ['id'])} saved for {getString(postTestReport, ['high_scale_request_id'])}.</p> : null}
            </CardContent>
          </Card>
        </div>
      ) : null}
      {output ? <Card><CardHeader><CardTitle>Action output</CardTitle></CardHeader><CardContent><pre className="codeblock">{output}</pre></CardContent></Card> : null}
    </div>
  );
}