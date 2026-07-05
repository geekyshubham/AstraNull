import { useEffect, useMemo, useRef, useState, type FormEvent } from 'react';
import { Activity, Bot, ClipboardList, FileCheck2, FileText, Network, ShieldCheck, ShieldHalf, Target, TriangleAlert, UserCog, Users } from 'lucide-react';
import { Badge } from '../components/ui/badge';
import { AnchorButton, Button } from '../components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../components/ui/card';
import { EmptyState } from '../components/ui/empty-state';
import { Progress } from '../components/ui/progress';
import { DataTable, type TableColumn } from '../components/ui/table';
import { Tabs } from '../components/ui/tabs';
import { buildApiHeaders, requestJson } from '../lib/api';
import { ROUTE_BY_ID } from '../lib/navigation';
import { buildDetailHref, getRouteEntityId } from '../lib/route-params';
import type { DataItem, PortalConfig, PortalData, RouteId, Session } from '../lib/types';
import { formatDate, formatExpectedBehavior, scoreTone } from '../lib/utils';
import { RunProofPanels, RunTimelineViz, TruthTablePanel, VerdictExplanationPanel } from '../components/runs/run-proof-panels';
import {
  agentHeartbeatFreshness,
  agentInstallApiBase,
  filterAgentAuditEntries,
  formatAgentCapabilities,
  formatAgentHealth,
  formatAgentPlacement
} from '../lib/agent-helpers';
import { routeTabs } from '../lib/prototype-manifest';
import { MetricCard, PageHeader } from './page-components';

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

type FactorEntry = { label: string; body: string; value: number };

function formatFactorLabel(value: string) {
  return value.replace(/_/g, ' ');
}

function buildEvidenceBackedFactors(
  route: RouteId,
  entity: DataItem,
  extras: { cveMatches: DataItem[] }
): FactorEntry[] {
  if (route === 'run-detail') {
    const placementScore = getNestedNumber(entity, ['verdict', 'placement_confidence', 'score'], NaN);
    const verdict = getNestedString(entity, ['verdict', 'verdict'], getString(entity, ['status'], 'pending'));
    const factors: FactorEntry[] = [];
    if (Number.isFinite(placementScore)) {
      factors.push({
        label: 'Placement confidence',
        body: getNestedString(entity, ['verdict', 'placement_confidence', 'level'], 'Recorded from verdict evidence.'),
        value: Math.round(placementScore)
      });
    }
    if (verdict !== 'pending') {
      factors.push({
        label: 'Verdict outcome',
        body: getNestedString(entity, ['verdict', 'explanation'], getNestedString(entity, ['verdict', 'conclusion'], 'Final verdict from `/v1/test-runs/:id`.')),
        value: verdict === 'pass' ? 100 : verdict === 'fail' ? 65 : 50
      });
    }
    return factors;
  }

  if (route === 'waf-asset-detail') {
    const riskFactors = getNestedArray(entity, ['current_posture', 'risk_factors']);
    if (riskFactors.length > 0) {
      return riskFactors.map((factor) => ({
        label: formatFactorLabel(getString(factor, ['factor'], 'risk factor')),
        body: getString(factor, ['value'], 'Recorded posture risk signal.'),
        value: Math.min(100, Math.max(0, getNestedNumber(factor, ['contribution'], 0)))
      }));
    }
    const passRate = getNestedNumber(entity, ['effectiveness', 'scenario_pass_rate'], NaN);
    if (Number.isFinite(passRate) && passRate > 0) {
      return [{
        label: 'Scenario pass rate',
        body: 'Latest effectiveness summary from `/v1/waf/assets/:id`.',
        value: Math.round(passRate)
      }];
    }
    return [];
  }

  if (route === 'cve-detail') {
    const triage = getNestedItem(entity, ['triage_result']);
    const factors: FactorEntry[] = [];
    if (triage && typeof triage.score === 'number' && Number.isFinite(triage.score)) {
      factors.push({
        label: 'Triage score',
        body: getString(triage, ['summary'], 'Exposure triage from `/v1/waf/cve-pipeline/:id/triage`.'),
        value: Math.min(100, Math.max(0, Math.round(triage.score)))
      });
    }
    const triageFactors = triage?.factors;
    if (triageFactors && typeof triageFactors === 'object' && !Array.isArray(triageFactors)) {
      for (const [key, active] of Object.entries(triageFactors)) {
        if (active === true) {
          factors.push({
            label: formatFactorLabel(key),
            body: 'Boolean triage factor returned by the CVE pipeline API.',
            value: 100
          });
        }
      }
    }
    if (extras.cveMatches.length > 0) {
      factors.push({
        label: 'Declared asset matches',
        body: `${extras.cveMatches.length} metadata-only matches from /v1/waf/cve-pipeline/:id/match.`,
        value: Math.min(100, extras.cveMatches.length * 20)
      });
    }
    return factors;
  }

  if (route === 'supply-chain-detail') {
    const confidence = getNestedNumber(entity, ['confidence'], NaN);
    if (Number.isFinite(confidence)) {
      return [{
        label: 'Exposure confidence',
        body: `${getString(entity, ['exposure_type'])} on ${getString(entity, ['hostname'])}.`,
        value: Math.round(confidence * 100)
      }];
    }
  }

  return [];
}

function FactorPanel({
  factors,
  emptyTitle = 'No evidence factors yet.',
  emptyBody = 'Factors appear after the backend returns entity-specific readiness or posture signals.'
}: {
  factors: FactorEntry[];
  emptyTitle?: string;
  emptyBody?: string;
}) {
  if (factors.length === 0) {
    return (
      <EmptyState
        icon={FileCheck2}
        title={emptyTitle}
        body={emptyBody}
      />
    );
  }
  return (
    <div className="factor-list">
      {factors.map((factor) => (
        <div className="factor" key={factor.label}>
          <div>
            <strong>{factor.label}</strong>
            <span>{factor.body}</span>
          </div>
          <Badge tone={scoreTone(factor.value)}>{factor.value}%</Badge>
          <Progress value={factor.value} />
        </div>
      ))}
    </div>
  );
}

function TimelinePanel({ items }: { items: Array<{ label: string; at?: unknown }> }) {
  if (items.length === 0) {
    return <p className="muted">No timeline milestones recorded for this entity.</p>;
  }
  return (
    <div className="timeline-list">
      {items.map((item, index) => (
        <div key={`${item.label}-${index}`}>
          <span>{index + 1}</span>
          <div>
            <strong>{item.label}</strong>
            <p>{formatDate(item.at)}</p>
          </div>
        </div>
      ))}
    </div>
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

  useEffect(() => {
    if (!enabled || !path) {
      setDetail(fallback);
      setLoading(false);
      return;
    }
    let cancelled = false;
    setLoading(true);
    setError('');
    requestJson(config, session, path)
      .then((payload) => {
        if (!cancelled) setDetail(payload as T);
      })
      .catch((err) => {
        if (!cancelled) {
          setDetail(fallback);
          setError(err instanceof Error ? err.message : 'Could not load entity detail.');
        }
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [config, session, path, enabled, fallback]);

  return { detail, error, loading };
}

function useListBackedDetail<T extends DataItem>(
  enabled: boolean,
  config: PortalConfig,
  session: Session,
  listPath: string,
  entityId: string,
  fallback: T | null
) {
  const [detail, setDetail] = useState<T | null>(fallback);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(enabled && Boolean(entityId));

  useEffect(() => {
    if (!enabled || !entityId) {
      setDetail(fallback);
      setLoading(false);
      return;
    }
    let cancelled = false;
    setLoading(true);
    setError('');
    requestJson(config, session, listPath)
      .then((payload) => {
        if (cancelled) return;
        const items = Array.isArray((payload as { items?: unknown }).items)
          ? (payload as { items: T[] }).items
          : [];
        const match = items.find((item) => getString(item, ['id'], '') === entityId) ?? null;
        setDetail(match ?? fallback);
        if (!match && !fallback) {
          setError('Entity not found in tenant list APIs.');
        }
      })
      .catch((err) => {
        if (!cancelled) {
          setDetail(fallback);
          setError(err instanceof Error ? err.message : 'Could not load entity detail.');
        }
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [config, session, listPath, enabled, entityId, fallback]);

  return { detail, error, loading };
}

function RunDetailView({
  entity,
  entityId,
  data,
  config,
  session,
  onRefresh,
  runEvents,
  loading,
  loadError
}: {
  entity: DataItem;
  entityId: string;
  data: PortalData;
  config: PortalConfig;
  session: Session;
  onRefresh: () => Promise<void>;
  runEvents: DataItem[];
  loading: boolean;
  loadError: string;
}) {
  const [tab, setTab] = useState('summary');
  const [busy, setBusy] = useState('');
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');
  const tabOptions = routeTabs('run-detail').map((item) => ({ id: item.id, label: item.label }));
  const verdict = entity.verdict as DataItem | undefined;
  const probeEvents = runEvents.filter((event) => getString(event, ['signal_type']) === 'probe_result');
  const agentEvents = runEvents.filter((event) => ['agent_observation', 'agent_no_observation'].includes(getString(event, ['signal_type'])));
  const relatedEvidence = data.evidence.filter((item) => getString(item, ['test_run_id'], '') === entityId);
  const relatedFindings = data.findings.filter((finding) => getString(finding, ['test_run_id'], '') === entityId);
  const status = getString(entity, ['status'], '');
  const cancellable = ['planned', 'running', 'collecting'].includes(status);

  async function runAction(label: string, action: () => Promise<unknown>, success: string) {
    setBusy(label);
    setError('');
    setMessage('');
    try {
      await action();
      setMessage(success);
      await onRefresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Action failed.');
    } finally {
      setBusy('');
    }
  }

  const milestoneTimeline = [
    { label: 'Run created', at: entity.created_at },
    { label: 'Run started', at: entity.started_at },
    { label: 'Probe window', at: entity.probe_started_at ?? entity.updated_at },
    { label: 'Verdict recorded', at: getNestedString(entity, ['verdict', 'finalized_at'], '') || entity.completed_at }
  ].filter((item) => item.at);

  return (
    <div className="content">
      <PageHeader route="run-detail" eyebrow="Entity detail" />
      {(message || error || loadError || loading) && (
        <div className={error || loadError ? 'form-banner error' : 'form-banner'}>
          {error || loadError || message || 'Loading run detail...'}
        </div>
      )}
      <Tabs value={tab} options={tabOptions} onChange={setTab} className="tabs-wrap" />
      {tab === 'summary' ? (
        <Card>
          <CardHeader>
            <CardTitle>{entityId}</CardTitle>
            <CardDescription>
              {getString(entity, ['check_id'])} · {getString(entity, ['status'])} · verdict {getNestedString(entity, ['verdict', 'verdict'], 'pending')}
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="kv-list">
              <div><span>Check</span><strong>{getString(entity, ['check_id'])}</strong></div>
              <div><span>Target group</span><strong>{getString(entity, ['target_group_id'])}</strong></div>
              <div><span>Target</span><strong>{getString(entity, ['target_id'])}</strong></div>
              <div><span>Vector</span><strong>{getString(entity, ['vector_family'], '—')}</strong></div>
              <div><span>Safety</span><strong>{getString(entity, ['safety_class'], '—')}</strong></div>
              <div><span>Verdict</span><strong>{getString(verdict ?? {}, ['verdict'], 'pending')}</strong></div>
              <div><span>Placement confidence</span><strong>{getNestedString(verdict ?? {}, ['placement_confidence', 'level'], 'unknown')}</strong></div>
              <div><span>Confidence</span><strong>{getString(verdict ?? {}, ['confidence'], '—')}</strong></div>
            </div>
            <RunProofPanels detail={entity} events={runEvents} />
            <div className="row-actions" style={{ marginTop: '1rem' }}>
              <AnchorButton size="sm" variant="secondary" href="#runs">Open test runs</AnchorButton>
              {cancellable ? (
                <>
                  <Button size="sm" variant="danger" disabled={busy !== ''} onClick={() => void runAction(`cancel-${entityId}`, () => requestJson(config, session, `/v1/test-runs/${entityId}/cancel`, { method: 'POST' }), 'Run cancelled.')}>Cancel</Button>
                  <Button size="sm" variant="ghost" disabled={busy !== ''} onClick={() => void runAction(`finalize-${entityId}`, () => requestJson(config, session, `/v1/test-runs/${entityId}/finalize`, { method: 'POST' }), 'Run finalized after observation window.')}>Finalize</Button>
                </>
              ) : null}
            </div>
          </CardContent>
        </Card>
      ) : null}
      {tab === 'timeline' ? (
        <Card>
          <CardHeader>
            <CardTitle>Timeline</CardTitle>
            <CardDescription>Ordered run lifecycle from scheduling through final verdict.</CardDescription>
          </CardHeader>
          <CardContent>
            <TimelinePanel items={milestoneTimeline} />
            <RunTimelineViz events={runEvents} />
            {runEvents.length > 0 ? (
              <div className="timeline-list">
                {runEvents.map((event, index) => (
                  <div key={getString(event, ['id'], String(index))}>
                    <span>{index + 1}</span>
                    <div>
                      <strong>{getString(event, ['signal_type', 'type'])}</strong>
                      <p>{formatDate(event.timestamp ?? event.created_at)} — {getString(event, ['source'], 'system')}</p>
                    </div>
                  </div>
                ))}
              </div>
            ) : <p className="muted">No run events recorded yet.</p>}
          </CardContent>
        </Card>
      ) : null}
      {tab === 'probe-results' ? (
        <Card>
          <CardHeader>
            <CardTitle>Probe results</CardTitle>
            <CardDescription>Outside observations from bounded probes.</CardDescription>
          </CardHeader>
          <CardContent>
            {probeEvents.length === 0 ? <p className="muted">No probe_result events for this run.</p> : (
              <div className="kv-list">
                {probeEvents.map((event, index) => (
                  <div key={getString(event, ['id'], String(index))}>
                    <span>{formatDate(event.timestamp ?? event.created_at)}</span>
                    <strong>{getNestedString(event, ['metadata', 'external_result'], getString(event, ['external_result'], getString(event, ['source'], 'probe_result')))}</strong>
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      ) : null}
      {tab === 'agent-observations' ? (
        <Card>
          <CardHeader>
            <CardTitle>Agent observations</CardTitle>
            <CardDescription>Inside observations from outbound-only canaries.</CardDescription>
          </CardHeader>
          <CardContent>
            {agentEvents.length === 0 ? <p className="muted">No agent observation events for this run.</p> : (
              <div className="kv-list">
                {agentEvents.map((event, index) => (
                  <div key={getString(event, ['id'], String(index))}>
                    <span>{getString(event, ['signal_type'])}</span>
                    <strong>{getString(event, ['agent_id'], getString(event, ['source'], 'agent'))} · {formatDate(event.timestamp ?? event.created_at)}</strong>
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      ) : null}
      {tab === 'correlation' ? (
        <Card>
          <CardHeader>
            <CardTitle>Correlation</CardTitle>
            <CardDescription>Truth table and verdict explanation from observed facts.</CardDescription>
          </CardHeader>
          <CardContent>
            <VerdictExplanationPanel detail={entity} events={runEvents} />
            <TruthTablePanel detail={entity} />
          </CardContent>
        </Card>
      ) : null}
      {tab === 'evidence' ? (
        <Card>
          <CardHeader>
            <CardTitle>Evidence</CardTitle>
            <CardDescription>Custody-ready artifacts generated by this run.</CardDescription>
          </CardHeader>
          <CardContent>
            {relatedEvidence.length === 0 ? <p className="muted">No evidence records linked to this run yet.</p> : (
              <div className="kv-list">
                {relatedEvidence.map((item) => (
                  <div key={getString(item, ['id'], '')}>
                    <span>{getString(item, ['kind', 'signal_type'], 'evidence')}</span>
                    <strong>{getString(item, ['id'])}</strong>
                  </div>
                ))}
              </div>
            )}
            {relatedFindings.length > 0 ? (
              <div className="row-actions" style={{ marginTop: '1rem' }}>
                <AnchorButton size="sm" variant="ghost" href="#findings">Open findings</AnchorButton>
              </div>
            ) : null}
          </CardContent>
        </Card>
      ) : null}
      {tab === 'events' ? (
        <Card>
          <CardHeader>
            <CardTitle>Raw events</CardTitle>
            <CardDescription>Sanitized event envelope review from `/v1/test-runs/:id/events`.</CardDescription>
          </CardHeader>
          <CardContent>
            {runEvents.length === 0 ? <p className="muted">No events recorded yet.</p> : (
              <div className="timeline-list">
                {runEvents.map((event, index) => (
                  <div key={getString(event, ['id'], String(index))}>
                    <span>{index + 1}</span>
                    <div>
                      <strong>{getString(event, ['signal_type', 'type'])}</strong>
                      <p>{formatDate(event.timestamp ?? event.created_at)} · {getString(event, ['source'], 'system')} · {getString(event, ['agent_id'], '—')}</p>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      ) : null}
    </div>
  );
}

const STAFF_ENTITLEMENT_FEATURES = ['waf_posture', 'external_discovery', 'connectors', 'high_scale_program'] as const;

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
  const [tab, setTab] = useState('overview');
  const [busy, setBusy] = useState('');
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');
  const [subscriptionSnapshot, setSubscriptionSnapshot] = useState<DataItem | null>(null);
  const [localDetail, setLocalDetail] = useState<DataItem | null>(detail);

  useEffect(() => {
    setLocalDetail(detail);
  }, [detail]);

  const resolvedDetail = localDetail;
  const tenant = getNestedItem(resolvedDetail, ['tenant']) ?? resolvedDetail;
  const account = getNestedItem(resolvedDetail, ['account']);
  const subscription = getNestedItem(resolvedDetail, ['subscription']) ?? subscriptionSnapshot;
  const users = getNestedArray(resolvedDetail, ['users']);
  const signupRequest = getNestedItem(resolvedDetail, ['signup_request']);
  const recentAudit = getNestedArray(resolvedDetail, ['recent_tenant_audit']);
  const relatedApprovals = data.internalApprovalRequests.filter(
    (item) => getString(item, ['tenant_id'], '') === entityId
  );
  const lifecycleState = getString(account, ['lifecycle_state'], 'active');
  const tabOptions = routeTabs('tenant-detail').map((item) => ({ id: item.id, label: item.label }));

  const effectiveEntitlements = getNestedItem(subscription, ['effective_entitlements'])
    ?? getNestedItem(subscriptionSnapshot, ['effective_entitlements']);

  useEffect(() => {
    if (!entityId || session.principal !== 'staff') {
      setSubscriptionSnapshot(null);
      return;
    }
    let cancelled = false;
    requestJson(config, session, `/internal/admin/tenants/${encodeURIComponent(entityId)}/subscription`)
      .then((payload) => {
        if (!cancelled) setSubscriptionSnapshot(payload as DataItem);
      })
      .catch(() => {
        if (!cancelled) setSubscriptionSnapshot(null);
      });
    return () => { cancelled = true; };
  }, [config, session, entityId, resolvedDetail]);

  async function reloadTenantDetail() {
    const [tenantPayload, subscriptionPayload] = await Promise.all([
      requestJson(config, session, `/internal/admin/tenants/${encodeURIComponent(entityId)}`),
      requestJson(config, session, `/internal/admin/tenants/${encodeURIComponent(entityId)}/subscription`).catch(() => null)
    ]);
    setLocalDetail(tenantPayload as DataItem);
    if (subscriptionPayload) setSubscriptionSnapshot(subscriptionPayload as DataItem);
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
      const payload = (err as Error & { payload?: unknown }).payload as { error?: string; message?: string } | undefined;
      setError(payload?.message ?? payload?.error ?? (err instanceof Error ? err.message : 'Staff action failed.'));
      return null;
    } finally {
      setBusy('');
    }
  }

  async function patchLifecycle(nextState: string) {
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
    await runStaffAction(`disable-${entityId}-${userId}`, () => requestJson(config, session, `/internal/admin/tenants/${encodeURIComponent(entityId)}/users/${encodeURIComponent(userId)}/disable`, {
      method: 'POST',
      body: { reason: 'Disabled from tenant detail.' }
    }), 'User disabled.');
  }

  const userColumns: TableColumn<DataItem>[] = [
    { key: 'email', label: 'Email', render: (item) => getString(item, ['email']) },
    { key: 'role', label: 'Role', render: (item) => <Badge tone="info">{getString(item, ['role'])}</Badge> },
    { key: 'status', label: 'Status', render: (item) => <Badge tone={getString(item, ['status']) === 'active' ? 'success' : 'warn'}>{getString(item, ['status'])}</Badge> },
    {
      key: 'actions',
      label: 'Actions',
      render: (item) => {
        const userId = getString(item, ['id'], '');
        if (getString(item, ['status']) === 'disabled') return '—';
        return (
          <div className="row-actions">
            <Button size="sm" variant="ghost" disabled={busy !== ''} onClick={() => void resendInvite(userId)}>Resend invite</Button>
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

  return (
    <div className="content">
      <PageHeader route="tenant-detail" eyebrow="Staff tenant operations" />
      <div className="page-head">
        <div>
          <h2>{getString(tenant, ['name'], entityId)}</h2>
          <p>
            <code>{entityId}</code> · {lifecycleState} · plan {getString(subscription, ['plan_id'], '—')} · {users.length} users
          </p>
        </div>
        <div className="row-actions">
          <AnchorButton size="sm" variant="secondary" href="#admin">Staff admin</AnchorButton>
          {lifecycleState !== 'active' ? (
            <Button size="sm" variant="secondary" disabled={busy !== ''} onClick={() => void patchLifecycle('active')}>Activate</Button>
          ) : (
            <Button size="sm" variant="danger" disabled={busy !== ''} onClick={() => void patchLifecycle('suspended')}>Suspend</Button>
          )}
        </div>
      </div>
      <div className="metric-grid four">
        <MetricCard label="Lifecycle" value={lifecycleState} sub="Account state from internal management API" icon={ShieldCheck} tone={lifecycleState === 'active' ? 'success' : 'warn'} />
        <MetricCard label="Users" value={users.length} sub="Tenant-scoped identities" icon={Users} tone="info" />
        <MetricCard label="Approvals" value={relatedApprovals.length} sub="Internal requests for this tenant" icon={ClipboardList} tone={relatedApprovals.length > 0 ? 'warn' : 'muted'} />
        <MetricCard label="Audit events" value={recentAudit.length} sub="Recent tenant-scoped audit entries" icon={FileCheck2} tone="muted" />
      </div>
      {(message || error || loadError || loading) && (
        <div className={error || loadError ? 'form-banner error' : 'form-banner'}>
          {error || loadError || message || 'Loading tenant detail...'}
        </div>
      )}
      <Tabs value={tab} options={tabOptions} onChange={setTab} className="tabs-wrap" />
      {tab === 'overview' ? (
        <div className="split">
          <Card>
            <CardHeader>
              <CardTitle>Tenant administration</CardTitle>
              <CardDescription>From `GET /internal/admin/tenants/:id`.</CardDescription>
            </CardHeader>
            <CardContent className="kv-list">
              <div><span>Tenant ID</span><strong><code>{entityId}</code></strong></div>
              <div><span>Name</span><strong>{getString(tenant, ['name'])}</strong></div>
              <div><span>Lifecycle</span><strong>{lifecycleState}</strong></div>
              <div><span>Region</span><strong>{getString(account, ['region'], '—')}</strong></div>
              <div><span>Support owner</span><strong>{getString(account, ['support_owner'], 'unassigned')}</strong></div>
              <div><span>Created</span><strong>{formatDate(tenant?.created_at)}</strong></div>
            </CardContent>
          </Card>
          <Card>
            <CardHeader>
              <CardTitle>Subscription</CardTitle>
              <CardDescription>Plan and entitlement summary for this tenant.</CardDescription>
            </CardHeader>
            <CardContent className="kv-list">
              <div><span>Plan</span><strong>{getString(subscription, ['plan_id'], '—')}</strong></div>
              <div><span>Status</span><strong>{getString(subscription, ['status'], '—')}</strong></div>
              <div><span>Effective from</span><strong>{formatDate(subscription?.effective_from ?? subscription?.created_at)}</strong></div>
              {effectiveEntitlements ? STAFF_ENTITLEMENT_FEATURES.map((feature) => (
                <div key={feature}>
                  <span>{feature}</span>
                  <strong>{effectiveEntitlements[feature] === true ? 'enabled' : 'disabled'}</strong>
                </div>
              )) : <p className="muted">Subscription entitlements load from the tenant subscription API.</p>}
            </CardContent>
          </Card>
        </div>
      ) : null}
      {tab === 'signup-queue' ? (
        <Card>
          <CardHeader>
            <CardTitle>Provisioning signup</CardTitle>
            <CardDescription>Signup request that created this tenant, if recorded.</CardDescription>
          </CardHeader>
          <CardContent>
            {signupRequest ? (
              <div className="kv-list">
                <div><span>Request ID</span><strong><code>{getString(signupRequest, ['id'])}</code></strong></div>
                <div><span>State</span><strong>{getString(signupRequest, ['state'])}</strong></div>
              </div>
            ) : (
              <EmptyState icon={ClipboardList} title="No linked signup request." body="Tenants provisioned outside the signup queue may not have a signup_request reference." actionLabel="Open staff admin" actionHref="#admin" />
            )}
          </CardContent>
        </Card>
      ) : null}
      {tab === 'tenants' ? (
        <>
          <Card>
            <CardHeader>
              <CardTitle>Tenant users</CardTitle>
              <CardDescription>Resend invites or disable users through staff support APIs.</CardDescription>
            </CardHeader>
            <CardContent>
              <DataTable columns={userColumns} items={users} empty={<EmptyState icon={Users} title="No users on this tenant." body="Provisioned tenants include an initial owner invite." />} />
            </CardContent>
          </Card>
          <div className="split">
            <Card>
              <CardHeader>
                <CardTitle>Support owner</CardTitle>
                <CardDescription>Patch through `PATCH /internal/admin/tenants/:id`.</CardDescription>
              </CardHeader>
              <CardContent>
                <form className="product-form" onSubmit={patchSupportOwner}>
                  <label className="full"><span>Support owner</span><input name="support_owner" defaultValue={getString(account, ['support_owner'], '')} placeholder="owner@customer.example" required /></label>
                  <div className="form-actions full"><Button type="submit" disabled={busy !== ''}>Save support owner</Button></div>
                </form>
              </CardContent>
            </Card>
            <Card>
              <CardHeader>
                <CardTitle>Entitlement grants</CardTitle>
                <CardDescription>Grant or revoke features through `POST /internal/admin/tenants/:id/entitlements`.</CardDescription>
              </CardHeader>
              <CardContent>
                <form className="product-form" onSubmit={grantEntitlement}>
                  <label>
                    <span>Feature</span>
                    <select name="feature" defaultValue="waf_posture">
                      {STAFF_ENTITLEMENT_FEATURES.map((feature) => <option key={feature} value={feature}>{feature}</option>)}
                    </select>
                  </label>
                  <label>
                    <span>Action</span>
                    <select name="enabled" defaultValue="true">
                      <option value="true">Grant / enable</option>
                      <option value="false">Revoke / disable</option>
                    </select>
                  </label>
                  <label className="full"><span>Reason</span><input name="reason" placeholder="Verified plan exception" required /></label>
                  <div className="form-actions full"><Button type="submit" disabled={busy !== ''}>Apply entitlement</Button></div>
                </form>
              </CardContent>
            </Card>
          </div>
        </>
      ) : null}
      {tab === 'approvals' ? (
        <Card>
          <CardHeader>
            <CardTitle>Approval requests</CardTitle>
            <CardDescription>Internal approvals scoped to this tenant.</CardDescription>
          </CardHeader>
          <CardContent>
            <DataTable columns={approvalColumns} items={relatedApprovals} empty={<EmptyState icon={ShieldCheck} title="No approval requests." body="Pending internal approvals for this tenant will appear here." actionLabel="Open staff admin" actionHref="#admin" />} />
          </CardContent>
        </Card>
      ) : null}
      {tab === 'audit' ? (
        <Card>
          <CardHeader>
            <CardTitle>Internal audit</CardTitle>
            <CardDescription>Recent tenant-scoped audit entries from tenant detail payload.</CardDescription>
          </CardHeader>
          <CardContent>
            <DataTable columns={auditColumns} items={recentAudit} empty={<EmptyState icon={FileCheck2} title="No audit events yet." body="Tenant security-relevant actions appear after staff or customer mutations are recorded." />} />
          </CardContent>
        </Card>
      ) : null}
    </div>
  );
}

function TargetGroupDetailView({
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

  const targets = getNestedArray(entity, ['targets']);
  const relatedRuns = data.runs.filter((run) => getString(run, ['target_group_id'], '') === entityId);
  const relatedFindings = data.findings.filter((finding) => getString(finding, ['target_group_id'], '') === entityId);
  const relatedAgents = data.agents.filter((agent) => getString(agent, ['target_group_id'], '') === entityId);
  const relatedPolicies = data.testPolicies.filter((policy) => getString(policy, ['target_group_id'], '') === entityId);
  const openFindings = relatedFindings.filter((finding) => getString(finding, ['status'], 'open') === 'open');
  const lastRun = [...relatedRuns].sort((left, right) => {
    const leftAt = String(left.updated_at ?? left.created_at ?? '');
    const rightAt = String(right.updated_at ?? right.created_at ?? '');
    return rightAt.localeCompare(leftAt);
  })[0] ?? null;

  const tabOptions = routeTabs('target-group-detail').map((item) => ({ id: item.id, label: item.label }));

  const targetColumns: TableColumn<DataItem>[] = [
    { key: 'kind', label: 'Type', render: (item) => <Badge tone="info">{getString(item, ['kind'])}</Badge> },
    { key: 'value', label: 'Target', render: (item) => getString(item, ['value']) },
    { key: 'expected', label: 'Expected behavior', render: (item) => formatExpectedBehavior(getString(item, ['expected_behavior'], '')) },
    { key: 'created', label: 'Created', render: (item) => formatDate(item.created_at) }
  ];

  const runColumns: TableColumn<DataItem>[] = [
    { key: 'id', label: 'Run', render: (item) => <code>{getString(item, ['id'])}</code> },
    { key: 'check', label: 'Check', render: (item) => getString(item, ['check_id']) },
    { key: 'status', label: 'Status', render: (item) => <Badge tone="info">{getString(item, ['status'], 'pending')}</Badge> },
    { key: 'when', label: 'When', render: (item) => formatDate(item.updated_at ?? item.created_at) },
    {
      key: 'actions',
      label: 'Actions',
      render: (item) => (
        <AnchorButton size="sm" variant="ghost" href={buildDetailHref('run-detail', getString(item, ['id'], ''))}>Open</AnchorButton>
      )
    }
  ];

  const findingColumns: TableColumn<DataItem>[] = [
    { key: 'id', label: 'Finding', render: (item) => <code>{getString(item, ['id'])}</code> },
    { key: 'severity', label: 'Severity', render: (item) => <Badge tone="danger">{getString(item, ['severity'], 'unknown')}</Badge> },
    { key: 'status', label: 'Status', render: (item) => <Badge tone="warn">{getString(item, ['status'], 'open')}</Badge> },
    { key: 'summary', label: 'Summary', render: (item) => getString(item, ['summary', 'title'], '—') }
  ];

  const agentColumns: TableColumn<DataItem>[] = [
    { key: 'hostname', label: 'Agent', render: (item) => getString(item, ['hostname', 'name', 'id']) },
    { key: 'status', label: 'Status', render: (item) => <Badge tone="success">{getString(item, ['status'], 'unknown')}</Badge> },
    { key: 'heartbeat', label: 'Last heartbeat', render: (item) => formatDate(item.last_heartbeat_at ?? item.updated_at) },
    {
      key: 'actions',
      label: 'Actions',
      render: (item) => (
        <AnchorButton size="sm" variant="ghost" href={buildDetailHref('agent-detail', getString(item, ['id'], ''))}>Detail</AnchorButton>
      )
    }
  ];

  const policyColumns: TableColumn<DataItem>[] = [
    { key: 'id', label: 'Policy', render: (item) => <code>{getString(item, ['id'])}</code> },
    { key: 'check', label: 'Check', render: (item) => getString(item, ['check_id']) },
    { key: 'cadence', label: 'Cadence', render: (item) => getString(item, ['cadence', 'schedule'], 'manual') },
    { key: 'enabled', label: 'Enabled', render: (item) => (item.enabled === false ? 'no' : 'yes') }
  ];

  async function runGroupAction(label: string, action: () => Promise<unknown>, success: string) {
    setBusy(label);
    setError('');
    setMessage('');
    try {
      await action();
      setMessage(success);
      await onRefresh();
    } catch (err) {
      const payload = (err as Error & { payload?: unknown }).payload as { error?: string; message?: string } | undefined;
      setError(payload?.message ?? payload?.error ?? (err instanceof Error ? err.message : 'Action failed.'));
    } finally {
      setBusy('');
    }
  }

  async function handlePatchGroup(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    await runGroupAction(`patch-target-group-${entityId}`, () => requestJson(config, session, `/v1/target-groups/${entityId}`, {
      method: 'PATCH',
      body: {
        name: String(form.get('name') ?? getString(entity, ['name'])).trim(),
        description: String(form.get('description') ?? '').trim(),
        expected_behavior_default: String(form.get('expected_behavior_default') ?? 'must_block_before_origin'),
        timezone: String(form.get('timezone') ?? 'UTC').trim() || 'UTC'
      }
    }), 'Target group settings saved.');
  }

  async function archiveGroup() {
    if (!window.confirm('Archive this target group?')) return;
    await runGroupAction(`archive-target-group-${entityId}`, () => requestJson(config, session, `/v1/target-groups/${entityId}`, {
      method: 'DELETE'
    }), 'Target group archived.');
    window.location.hash = '#target-groups';
  }

  return (
    <div className="content">
      <PageHeader route="target-group-detail" eyebrow="Declared business service" />
      <div className="page-head">
        <div>
          <h2>{getString(entity, ['name', 'id'])}</h2>
          <p>
            {targets.length} declared targets · {getString(entity, ['environment_id'], 'tenant scope')} · expected {formatExpectedBehavior(getString(entity, ['expected_behavior_default'], 'must_block_before_origin'))}
          </p>
        </div>
        <div className="row-actions">
          <AnchorButton size="sm" variant="secondary" href="#target-groups">All groups</AnchorButton>
          <AnchorButton size="sm" variant="default" href="#runs">Run checks</AnchorButton>
        </div>
      </div>
      <div className="metric-grid four">
        <MetricCard label="Targets" value={targets.length} sub="Declared · never auto-discovered" icon={Target} tone="info" />
        <MetricCard label="Bound agents" value={relatedAgents.length} sub="Outbound observers for this group" icon={Bot} tone="success" />
        <MetricCard label="Open findings" value={openFindings.length} sub="Unresolved gaps on this group" icon={TriangleAlert} tone={openFindings.length > 0 ? 'danger' : 'muted'} />
        <MetricCard label="Last run" value={lastRun ? getString(lastRun, ['id']) : '—'} sub={lastRun ? formatDate(lastRun.updated_at ?? lastRun.created_at) : 'No runs yet'} icon={Activity} tone="muted" />
      </div>
      {(message || error || loadError || loading) && (
        <div className={error || loadError ? 'form-banner error' : 'form-banner'}>
          {error || loadError || message || 'Loading target group detail...'}
        </div>
      )}
      <Tabs value={tab} options={tabOptions} onChange={setTab} className="tabs-wrap" />
      {tab === 'overview' ? (
        <div className="split">
          <Card>
            <CardHeader>
              <CardTitle>Group summary</CardTitle>
              <CardDescription>Fields from `/v1/target-groups/{'{id}'}`.</CardDescription>
            </CardHeader>
            <CardContent className="kv-list">
              <div><span>Group ID</span><strong><code>{entityId}</code></strong></div>
              <div><span>Environment</span><strong>{getString(entity, ['environment_id'])}</strong></div>
              <div><span>Default expected behavior</span><strong>{formatExpectedBehavior(getString(entity, ['expected_behavior_default'], 'must_block_before_origin'))}</strong></div>
              <div><span>Timezone</span><strong>{getString(entity, ['timezone'], 'UTC')}</strong></div>
              <div><span>Created</span><strong>{formatDate(entity.created_at)}</strong></div>
              <div><span>Description</span><strong>{getString(entity, ['description'], 'No description recorded.')}</strong></div>
            </CardContent>
          </Card>
          <Card>
            <CardHeader>
              <CardTitle>Validation posture</CardTitle>
              <CardDescription>Counts derived from tenant list APIs for this group.</CardDescription>
            </CardHeader>
            <CardContent className="kv-list">
              <div><span>Recent runs</span><strong>{relatedRuns.length}</strong></div>
              <div><span>Bound policies</span><strong>{relatedPolicies.length}</strong></div>
              <div><span>Evidence records</span><strong>{data.evidence.filter((item) => getString(item, ['target_group_id'], '') === entityId).length}</strong></div>
              <div><span>Latest run status</span><strong>{lastRun ? getString(lastRun, ['status'], 'pending') : 'none'}</strong></div>
            </CardContent>
          </Card>
        </div>
      ) : null}
      {tab === 'targets' ? (
        <Card>
          <CardHeader>
            <div>
              <CardTitle>Declared targets</CardTitle>
              <CardDescription>Manual declarations loaded from the target-group detail API.</CardDescription>
            </div>
            <Badge tone="success">{targets.length} targets</Badge>
          </CardHeader>
          <CardContent>
            <DataTable
              columns={targetColumns}
              items={targets}
              empty={<EmptyState icon={Target} title="No targets declared." body="Add targets from the Target Groups page." actionLabel="Open Target Groups" actionHref="#target-groups" />}
            />
            <div className="form-actions">
              <AnchorButton size="sm" variant="secondary" href="#target-groups">Manage targets</AnchorButton>
            </div>
          </CardContent>
        </Card>
      ) : null}
      {tab === 'expected-behavior' ? (
        <Card>
          <CardHeader>
            <CardTitle>Expected behavior</CardTitle>
            <CardDescription>Customer-declared protection expectations for this group.</CardDescription>
          </CardHeader>
          <CardContent className="kv-list">
            <div><span>Group default</span><strong>{formatExpectedBehavior(getString(entity, ['expected_behavior_default'], 'must_block_before_origin'))}</strong></div>
            <div><span>Safety policy</span><strong>{getNestedString(entity, ['safety_policy', 'max_concurrent_runs'], '1')} concurrent runs · {getNestedString(entity, ['safety_policy', 'min_seconds_between_runs'], '300')}s cooldown</strong></div>
            <div><span>Per-target overrides</span><strong>{targets.filter((target) => getString(target, ['expected_behavior']) !== getString(entity, ['expected_behavior_default'], 'must_block_before_origin')).length}</strong></div>
          </CardContent>
          <CardContent>
            <DataTable
              columns={[
                { key: 'value', label: 'Target', render: (item) => getString(item, ['value']) },
                { key: 'expected', label: 'Expected behavior', render: (item) => formatExpectedBehavior(getString(item, ['expected_behavior'], getString(entity, ['expected_behavior_default'], 'must_block_before_origin'))) }
              ]}
              items={targets}
              empty={<EmptyState icon={ShieldHalf} title="No target-level behavior yet." body="Add declared targets to attach expected behavior." />}
            />
          </CardContent>
        </Card>
      ) : null}
      {tab === 'agents' ? (
        <Card>
          <CardHeader>
            <CardTitle>Bound agents</CardTitle>
            <CardDescription>Outbound observers scoped to this target group.</CardDescription>
          </CardHeader>
          <CardContent>
            <DataTable
              columns={agentColumns}
              items={relatedAgents}
              empty={<EmptyState icon={Bot} title="No agents bound." body="Install an outbound agent and bind it to this declared group." actionLabel="Open agents" actionHref="#agents" />}
            />
          </CardContent>
        </Card>
      ) : null}
      {tab === 'checks' ? (
        <Card>
          <CardHeader>
            <CardTitle>Checks on this group</CardTitle>
            <CardDescription>Safe test policies bound to this declared group.</CardDescription>
          </CardHeader>
          <CardContent>
            <DataTable
              columns={policyColumns}
              items={relatedPolicies}
              empty={<EmptyState icon={FileCheck2} title="No policies bound." body="Bind safe checks through test policies before scheduling runs." actionLabel="Open test policies" actionHref="#test-policies" />}
            />
          </CardContent>
        </Card>
      ) : null}
      {tab === 'runs' ? (
        <Card>
          <CardHeader>
            <CardTitle>Recent runs</CardTitle>
            <CardDescription>Validation runs filtered by `target_group_id`.</CardDescription>
          </CardHeader>
          <CardContent>
            <DataTable
              columns={runColumns}
              items={relatedRuns}
              empty={<EmptyState icon={Activity} title="No runs yet." body="Start a safe run after declaring targets and binding checks." actionLabel="Open test runs" actionHref="#runs" />}
            />
          </CardContent>
        </Card>
      ) : null}
      {tab === 'findings' ? (
        <Card>
          <CardHeader>
            <CardTitle>Findings on this group</CardTitle>
            <CardDescription>Open and closed gaps tied to this declared scope.</CardDescription>
          </CardHeader>
          <CardContent>
            <DataTable
              columns={findingColumns}
              items={relatedFindings}
              empty={<EmptyState icon={TriangleAlert} title="No findings recorded." body="Findings appear after validation runs surface gaps." actionLabel="Open findings" actionHref="#findings" />}
            />
          </CardContent>
        </Card>
      ) : null}
      {tab === 'settings' ? (
        <Card>
          <CardHeader>
            <CardTitle>Group settings</CardTitle>
            <CardDescription>Patch declaration metadata without changing unrelated inventory.</CardDescription>
          </CardHeader>
          <CardContent>
            <form key={entityId} className="product-form" onSubmit={handlePatchGroup}>
              <label>
                <span>Name</span>
                <input name="name" defaultValue={getString(entity, ['name'])} />
              </label>
              <label>
                <span>Timezone</span>
                <input name="timezone" defaultValue={getString(entity, ['timezone'], 'UTC')} />
              </label>
              <label className="full">
                <span>Description</span>
                <textarea name="description" rows={3} defaultValue={getString(entity, ['description'], '')} />
              </label>
              <label className="full">
                <span>Default expected behavior</span>
                <select name="expected_behavior_default" defaultValue={getString(entity, ['expected_behavior_default'], 'must_block_before_origin')}>
                  <option value="must_block_before_origin">Must be blocked before origin</option>
                  <option value="must_allow_baseline_health">Must allow baseline health</option>
                  <option value="must_challenge_or_rate_limit">Must challenge or rate-limit</option>
                  <option value="must_not_expose_direct_ip">Must not expose direct IP</option>
                </select>
              </label>
              <div className="form-actions full">
                <Button type="submit" disabled={busy !== ''}>Save settings</Button>
                <AnchorButton size="sm" variant="secondary" href="#target-groups">Manage targets</AnchorButton>
                <Button type="button" variant="danger" disabled={busy !== ''} onClick={() => void archiveGroup()}>Archive group</Button>
              </div>
            </form>
          </CardContent>
        </Card>
      ) : null}
    </div>
  );
}

function AgentDetailView({
  entity,
  entityId,
  data,
  config,
  session,
  onRefresh
}: {
  entity: DataItem;
  entityId: string;
  data: PortalData;
  config: PortalConfig;
  session: Session;
  onRefresh: () => Promise<void>;
}) {
  const [tab, setTab] = useState('fleet');
  const [busy, setBusy] = useState('');
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');
  const [placementReviews, setPlacementReviews] = useState<DataItem | null>(null);
  const [updateReleases, setUpdateReleases] = useState<DataItem[]>([]);
  const [trustKeys, setTrustKeys] = useState<DataItem[]>([]);
  const [auxLoading, setAuxLoading] = useState(false);
  const tabOptions = routeTabs('agent-detail').map((item) => ({ id: item.id, label: item.label }));
  const targetGroupId = getString(entity, ['target_group_id'], '');
  const placementReview = Array.isArray(placementReviews?.reviews)
    ? (placementReviews.reviews as DataItem[]).find((review) => getString(review, ['target_group_id'], '') === targetGroupId)
    : null;
  const agentLogs = filterAgentAuditEntries(data.audit, entityId);
  const installToken = '<BOOTSTRAP_TOKEN>';
  const apiBase = agentInstallApiBase();

  useEffect(() => {
    if (!['placement', 'install'].includes(tab)) return undefined;
    let cancelled = false;
    setAuxLoading(true);
    const query = targetGroupId ? `/v1/placement/reviews?target_group_id=${encodeURIComponent(targetGroupId)}` : '/v1/placement/reviews';
    requestJson(config, session, query)
      .then((payload) => { if (!cancelled) setPlacementReviews(payload as DataItem); })
      .catch(() => { if (!cancelled) setPlacementReviews(null); })
      .finally(() => { if (!cancelled) setAuxLoading(false); });
    return () => { cancelled = true; };
  }, [tab, config, session, targetGroupId]);

  useEffect(() => {
    if (tab !== 'upgrades') return undefined;
    let cancelled = false;
    setAuxLoading(true);
    Promise.all([
      requestJson(config, session, '/v1/agent-updates'),
      requestJson(config, session, '/v1/agent-update-trust-keys')
    ])
      .then(([releasesPayload, trustPayload]) => {
        if (cancelled) return;
        setUpdateReleases(Array.isArray((releasesPayload as { items?: unknown }).items) ? (releasesPayload as { items: DataItem[] }).items : []);
        setTrustKeys(Array.isArray((trustPayload as { items?: unknown }).items) ? (trustPayload as { items: DataItem[] }).items : []);
      })
      .catch(() => {
        if (!cancelled) {
          setUpdateReleases([]);
          setTrustKeys([]);
        }
      })
      .finally(() => { if (!cancelled) setAuxLoading(false); });
    return () => { cancelled = true; };
  }, [tab, config, session]);

  async function revokeAgent() {
    if (!entityId || getString(entity, ['status']) === 'revoked') return;
    setBusy(`revoke-${entityId}`);
    setError('');
    setMessage('');
    try {
      await requestJson(config, session, `/v1/agents/${encodeURIComponent(entityId)}/revoke`, { method: 'POST' });
      setMessage('Agent revoked.');
      await onRefresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Agent revoke failed.');
    } finally {
      setBusy('');
    }
  }

  return (
    <div className="content">
      <PageHeader route="agent-detail" eyebrow="Outbound observer" />
      <div className="page-head">
        <div>
          <h2>{getString(entity, ['hostname', 'name', 'id'])}</h2>
          <p>
            <code>{entityId}</code> · {getString(entity, ['status'], 'unknown')} · {formatAgentCapabilities(entity)}
          </p>
        </div>
        <div className="row-actions">
          {getString(entity, ['status']) !== 'revoked' ? (
            <Button size="sm" variant="danger" disabled={busy !== ''} onClick={() => void revokeAgent()}>Revoke agent</Button>
          ) : null}
          <AnchorButton size="sm" variant="secondary" href="#agents">Back to fleet</AnchorButton>
        </div>
      </div>
      {(message || error) && <div className={error ? 'form-banner error' : 'form-banner'}>{error || message}</div>}
      <Tabs value={tab} options={tabOptions} onChange={setTab} className="tabs-wrap" />
      {tab === 'fleet' || tab === 'overview' ? (
        <div className="split">
          <Card>
            <CardHeader>
              <CardTitle>Agent identity</CardTitle>
              <CardDescription>Outbound observer metadata from <code>GET /v1/agents</code>.</CardDescription>
            </CardHeader>
            <CardContent className="kv-list">
              <div><span>Hostname</span><strong>{getString(entity, ['hostname', 'name'])}</strong></div>
              <div><span>Environment</span><strong>{getString(entity, ['environment_id'], 'tenant scope')}</strong></div>
              <div><span>Target group</span><strong>{targetGroupId || 'unbound'}</strong></div>
              <div><span>Health</span><strong>{formatAgentHealth(entity)}</strong></div>
              <div><span>Placement</span><strong>{formatAgentPlacement(entity)}</strong></div>
              <div><span>Last heartbeat</span><strong>{formatDate(entity.last_heartbeat_at ?? entity.updated_at)}</strong></div>
              <div><span>Version</span><strong>{getString(entity, ['version'], 'unknown')}</strong></div>
              <div><span>Gateway fingerprint</span><strong>{getString(entity, ['fingerprint'], 'not registered')}</strong></div>
            </CardContent>
          </Card>
          <Card>
            <CardHeader>
              <CardTitle>Actions</CardTitle>
              <CardDescription>Lifecycle controls for this outbound observer.</CardDescription>
            </CardHeader>
            <CardContent className="row-actions">
              {getString(entity, ['status']) !== 'revoked' ? (
                <Button size="sm" variant="danger" disabled={busy !== ''} onClick={() => void revokeAgent()}>Revoke agent</Button>
              ) : null}
              <AnchorButton size="sm" variant="secondary" href="#agents">Back to fleet</AnchorButton>
            </CardContent>
          </Card>
        </div>
      ) : null}
      {tab === 'install' ? (
        <Card>
          <CardHeader>
            <CardTitle>Install reference</CardTitle>
            <CardDescription>Install commands use a fresh bootstrap token from <code>#agents</code> or <code>#settings</code>.</CardDescription>
          </CardHeader>
          <CardContent>
            <pre className="codeblock">{`curl -fsSL ${apiBase}/agents/install.sh \\
  | sudo ASTRANULL_API_URL="${apiBase}" \\
       ASTRANULL_BOOTSTRAP_TOKEN="${installToken}" bash`}</pre>
          </CardContent>
        </Card>
      ) : null}
      {tab === 'health' ? (
        <Card>
          <CardHeader>
            <CardTitle>Health signals</CardTitle>
            <CardDescription>Heartbeat freshness derived from agent record timestamps.</CardDescription>
          </CardHeader>
          <CardContent className="kv-list">
            <div><span>Heartbeat freshness</span><strong>{agentHeartbeatFreshness(entity)}</strong></div>
            <div><span>Last heartbeat</span><strong>{formatDate(entity.last_heartbeat_at)}</strong></div>
            <div><span>Status</span><strong>{getString(entity, ['status'], 'unknown')}</strong></div>
            <div><span>Version</span><strong>{getString(entity, ['version'], 'unknown')}</strong></div>
          </CardContent>
        </Card>
      ) : null}
      {tab === 'placement' ? (
        <Card>
          <CardHeader>
            <CardTitle>Placement review</CardTitle>
            <CardDescription>Target-group placement confidence from <code>GET /v1/placement/reviews</code>.</CardDescription>
          </CardHeader>
          <CardContent className="kv-list">
            {auxLoading ? <p className="muted">Loading placement review…</p> : null}
            <div><span>Target group</span><strong>{targetGroupId || 'unbound'}</strong></div>
            <div><span>Placement status</span><strong>{getString(placementReview, ['status'], 'unknown')}</strong></div>
            <div><span>Observation mode</span><strong>{getString(placementReview, ['observation_mode'], '—')}</strong></div>
            <div><span>Summary</span><strong>{getString(placementReview, ['summary'], getNestedString(placementReviews, ['summary', 'summary'], 'Awaiting baseline traffic evidence.'))}</strong></div>
          </CardContent>
        </Card>
      ) : null}
      {tab === 'capabilities' ? (
        <Card>
          <CardHeader>
            <CardTitle>Capabilities</CardTitle>
            <CardDescription>Observation modes reported on registration and heartbeat.</CardDescription>
          </CardHeader>
          <CardContent className="kv-list">
            <div><span>Modes</span><strong>{formatAgentCapabilities(entity)}</strong></div>
            <div><span>Placement</span><strong>{formatAgentPlacement(entity)}</strong></div>
            <div><span>Group placement status</span><strong>{getString(placementReview, ['status'], '—')}</strong></div>
          </CardContent>
        </Card>
      ) : null}
      {tab === 'logs' ? (
        <Card>
          <CardHeader>
            <CardTitle>Audit trail</CardTitle>
            <CardDescription>Metadata-only lifecycle events for this agent from <code>GET /v1/audit-log</code>.</CardDescription>
          </CardHeader>
          <CardContent>
            {agentLogs.length === 0 ? (
              <EmptyState icon={ClipboardList} title="No audit events for this agent yet." body="Registration, heartbeat, revoke, and update actions appear after lifecycle activity." />
            ) : (
              <div className="kv-list">
                {agentLogs.slice(0, 12).map((entry, index) => (
                  <div key={getString(entry, ['id'], String(index))}>
                    <span>{getString(entry, ['action'])}</span>
                    <strong>{formatDate(entry.created_at ?? entry.timestamp)}</strong>
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      ) : null}
      {tab === 'upgrades' ? (
        <div className="split">
          <Card>
            <CardHeader>
              <CardTitle>Eligible releases</CardTitle>
              <CardDescription>Tenant releases from <code>GET /v1/agent-updates</code>; agent polls update channel with its credential.</CardDescription>
            </CardHeader>
            <CardContent>
              {auxLoading ? <p className="muted">Loading releases…</p> : null}
              {updateReleases.length === 0 ? <p className="muted">No published releases for this tenant.</p> : null}
              <div className="kv-list">
                {updateReleases.slice(0, 8).map((release) => (
                  <div key={getString(release, ['id'], '')}>
                    <span>{getString(release, ['version'])} ({getString(release, ['channel'], 'stable')})</span>
                    <strong>{getString(release, ['state'], 'active')}</strong>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
          <Card>
            <CardHeader>
              <CardTitle>Trust keys</CardTitle>
              <CardDescription>Active signing keys from <code>GET /v1/agent-update-trust-keys</code>.</CardDescription>
            </CardHeader>
            <CardContent className="kv-list">
              {trustKeys.length === 0 ? <p className="muted">No trust keys registered.</p> : null}
              {trustKeys.map((key) => (
                <div key={getString(key, ['id'], '')}>
                  <span>{getString(key, ['name'])}</span>
                  <strong>{getString(key, ['status'])}</strong>
                </div>
              ))}
            </CardContent>
          </Card>
        </div>
      ) : null}
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
  const [tab, setTab] = useState('overview');
  const [busy, setBusy] = useState('');
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');
  const [runEvents, setRunEvents] = useState<DataItem[]>([]);
  const [cveMatches, setCveMatches] = useState<DataItem[]>([]);
  const [cvePlaybook, setCvePlaybook] = useState<DataItem | null>(null);
  const [cveAuxError, setCveAuxError] = useState('');
  const [cveAuxLoading, setCveAuxLoading] = useState(false);
  const entityId = useMemo(() => {
    const fallbackByRoute: Partial<Record<RouteId, string>> = {
      'target-group-detail': getString(data.targetGroups[0] ?? null, ['id'], ''),
      'agent-detail': getString(data.agents[0] ?? null, ['id'], ''),
      'run-detail': getString(data.runs[0] ?? null, ['id'], ''),
      'waf-asset-detail': getString(data.wafAssets[0] ?? null, ['id'], ''),
      'cve-detail': getString(data.cvePipeline[0] ?? null, ['id'], ''),
      'supply-chain-detail': getString(data.supplyChainRisks[0] ?? null, ['id'], ''),
      'discovery-entity': getString(data.discoveryEntities[0] ?? data.discoveryCandidates[0] ?? null, ['id', 'entity_id'], ''),
      'tenant-detail': getString(data.internalTenants[0] ?? null, ['tenant_id', 'id'], '')
    };
    return getRouteEntityId(fallbackByRoute[route] ?? '');
  }, [route, data]);

  const targetGroupFallback = data.targetGroups.find((item) => getString(item, ['id'], '') === entityId) ?? null;
  const agentFallback = data.agents.find((item) => getString(item, ['id'], '') === entityId) ?? null;
  const runFallback = data.runs.find((item) => getString(item, ['id'], '') === entityId) ?? null;
  const wafFallback = data.wafAssets.find((item) => getString(item, ['id'], '') === entityId) ?? null;
  const discoveryFallback =
    data.discoveryEntities.find((item) => getString(item, ['id', 'entity_id'], '') === entityId)
    ?? data.discoveryCandidates.find((item) => getString(item, ['id', 'entity_id'], '') === entityId)
    ?? null;
  const tenantFallback = data.internalTenants.find((item) => getString(item, ['tenant_id', 'id'], '') === entityId) ?? null;
  const cveFallback = data.cvePipeline.find((item) => getString(item, ['id'], '') === entityId) ?? null;
  const supplyChainFallback = data.supplyChainRisks.find((item) => getString(item, ['id'], '') === entityId) ?? null;

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
  const wafDetail = useEntityDetail(
    route === 'waf-asset-detail' && Boolean(entityId),
    config,
    session,
    `/v1/waf/assets/${encodeURIComponent(entityId)}`,
    wafFallback
  );
  const supplyChainDetail = useEntityDetail(
    route === 'supply-chain-detail' && Boolean(entityId),
    config,
    session,
    `/v1/waf/supply-chain/risks/${encodeURIComponent(entityId)}`,
    supplyChainFallback
  );
  const cveDetail = useListBackedDetail(
    route === 'cve-detail' && Boolean(entityId),
    config,
    session,
    '/v1/waf/cve-pipeline',
    entityId,
    cveFallback
  );
  const tenantDetail = useEntityDetail(
    route === 'tenant-detail' && Boolean(entityId) && session.principal === 'staff',
    config,
    session,
    `/internal/admin/tenants/${encodeURIComponent(entityId)}`,
    null
  );

  const detailState =
    route === 'target-group-detail' ? targetGroupDetail
      : route === 'run-detail' ? runDetail
        : route === 'waf-asset-detail' ? wafDetail
          : route === 'supply-chain-detail' ? supplyChainDetail
            : route === 'cve-detail' ? cveDetail
              : { detail: null as DataItem | null, error: '', loading: false };

  const entity =
    route === 'agent-detail' ? agentFallback
      : route === 'discovery-entity' ? discoveryFallback
        : route === 'tenant-detail' ? tenantFallback
          : detailState.detail;

  const groupId = route === 'target-group-detail'
    ? getString(entity, ['id'], '')
    : getString(entity, ['target_group_id'], '');
  const relatedRuns = data.runs.filter((run) => getString(run, ['target_group_id'], '') === groupId);
  const relatedFindings = data.findings.filter((finding) => getString(finding, ['target_group_id'], '') === groupId);
  const relatedAgents = data.agents.filter((agent) => getString(agent, ['target_group_id'], '') === groupId);
  const relatedEvidence = data.evidence.filter((item) => getString(item, ['test_run_id'], '') === entityId || getString(item, ['target_group_id'], '') === groupId);
  const targets = route === 'target-group-detail' ? getNestedArray(entity, ['targets']) : [];

  useEffect(() => {
    if (route !== 'cve-detail' || !entityId) {
      setCveMatches([]);
      setCvePlaybook(null);
      setCveAuxError('');
      setCveAuxLoading(false);
      return;
    }
    let cancelled = false;
    setCveAuxLoading(true);
    setCveAuxError('');
    Promise.allSettled([
      requestJson(config, session, `/v1/waf/cve-pipeline/${encodeURIComponent(entityId)}/playbook`),
      requestJson(config, session, `/v1/waf/cve-pipeline/${encodeURIComponent(entityId)}/match`, { method: 'POST', body: {} })
    ])
      .then(([playbookResult, matchResult]) => {
        if (cancelled) return;
        const errors: string[] = [];
        if (playbookResult.status === 'fulfilled') {
          const playbookPayload = playbookResult.value as { playbook?: DataItem } | DataItem;
          setCvePlaybook(getNestedItem(playbookPayload as DataItem, ['playbook']) ?? (playbookPayload as DataItem));
        } else {
          setCvePlaybook(null);
          const reason = playbookResult.reason;
          errors.push(reason instanceof Error ? reason.message : 'CVE playbook fetch failed.');
        }
        if (matchResult.status === 'fulfilled') {
          const matchPayload = matchResult.value as { matches?: unknown };
          const matches = Array.isArray(matchPayload?.matches) ? matchPayload.matches as DataItem[] : [];
          setCveMatches(matches);
        } else {
          setCveMatches([]);
          const reason = matchResult.reason;
          errors.push(reason instanceof Error ? reason.message : 'CVE asset match fetch failed.');
        }
        setCveAuxError(errors.join(' '));
      })
      .finally(() => {
        if (!cancelled) setCveAuxLoading(false);
      });
    return () => { cancelled = true; };
  }, [route, entityId, config, session]);

  useEffect(() => {
    if (route !== 'run-detail' || !entityId) {
      setRunEvents([]);
      return;
    }
    let cancelled = false;
    requestJson(config, session, `/v1/test-runs/${encodeURIComponent(entityId)}/events`)
      .then((payload) => {
        if (cancelled) return;
        const items = Array.isArray((payload as { items?: unknown }).items) ? (payload as { items: DataItem[] }).items : [];
        setRunEvents(items);
      })
      .catch(() => {
        if (!cancelled) setRunEvents([]);
      });
    return () => { cancelled = true; };
  }, [route, entityId, config, session]);

  async function runDetailAction(label: string, action: () => Promise<unknown>, success: string) {
    setBusy(label);
    setError('');
    setMessage('');
    try {
      await action();
      setMessage(success);
      await onRefresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Action failed.');
    } finally {
      setBusy('');
    }
  }

  async function revokeAgent(agentId: string) {
    if (!agentId) return;
    setBusy(`revoke-${agentId}`);
    setError('');
    setMessage('');
    try {
      await requestJson(config, session, `/v1/agents/${encodeURIComponent(agentId)}/revoke`, { method: 'POST' });
      setMessage('Agent revoked.');
      await onRefresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Agent revoke failed.');
    } finally {
      setBusy('');
    }
  }

  const factors = useMemo(() => {
    if (!entity) return [];
    return buildEvidenceBackedFactors(route, entity, { cveMatches });
  }, [entity, route, cveMatches]);

  const factorsTitle = factors.length > 0 ? 'Evidence-backed factors' : 'Derived summary';
  const factorsDescription = factors.length > 0
    ? 'Scores and signals returned by tenant entity APIs.'
    : 'No backend factor payload is available for this entity yet.';
  const factorsEmptyTitle = factors.length > 0 ? 'No evidence factors yet.' : 'No backend factors yet.';
  const factorsEmptyBody = factors.length > 0
    ? 'Factors appear after the backend returns entity-specific readiness or posture signals.'
    : 'Run the route-specific API actions (triage, validation, posture finalize) to populate factor data.';

  const timeline = useMemo(() => {
    if (!entity) return [];
    if (route === 'run-detail') {
      return [
        { label: 'Run created', at: entity.created_at },
        { label: 'Run started', at: entity.started_at },
        { label: 'Probe window', at: entity.probe_started_at ?? entity.updated_at },
        { label: 'Verdict recorded', at: getNestedString(entity, ['verdict', 'finalized_at'], '') || entity.completed_at }
      ].filter((item) => item.at);
    }
    return [
      { label: 'Record created', at: entity.created_at },
      { label: 'Last updated', at: entity.updated_at },
      { label: 'Latest evidence', at: relatedRuns[0]?.updated_at ?? relatedRuns[0]?.created_at },
      { label: 'Latest finding', at: relatedFindings[0]?.updated_at ?? relatedFindings[0]?.created_at }
    ].filter((item) => item.at);
  }, [entity, route, relatedFindings, relatedRuns]);

  const targetColumns: TableColumn<DataItem>[] = [
    { key: 'kind', label: 'Type', render: (item) => <Badge tone="info">{getString(item, ['kind'])}</Badge> },
    { key: 'value', label: 'Target', render: (item) => getString(item, ['value']) },
    { key: 'expected', label: 'Expected behavior', render: (item) => getString(item, ['expected_behavior']) }
  ];

  if (route === 'tenant-detail') {
    if (!entityId) {
      return (
        <div className="content">
          <PageHeader route={route} eyebrow="Staff tenant operations" />
          <EmptyState icon={Target} title="No tenant selected." body="Open a tenant from the staff directory with ?id= or use the Detail link on #admin." actionLabel="Open staff admin" actionHref="#admin" />
        </div>
      );
    }
    if (session.principal !== 'staff') {
      return (
        <div className="content">
          <PageHeader route={route} eyebrow="Staff tenant operations" />
          <EmptyState icon={UserCog} title="Staff session required." body="Tenant detail loads internal management APIs after staff authentication." actionLabel="Open staff login" actionHref="/internal/admin/login" />
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
        onRefresh={onRefresh}
        loading={tenantDetail.loading}
        loadError={tenantDetail.error}
      />
    );
  }

  if (route === 'target-group-detail') {
    if (!entityId) {
      return (
        <div className="content">
          <PageHeader route={route} eyebrow="Declared business service" />
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
          <PageHeader route={route} eyebrow="Declared business service" />
          <div className="form-banner">Loading target group detail...</div>
        </div>
      );
    }
    if (!entity) {
      return (
        <div className="content">
          <PageHeader route={route} eyebrow="Declared business service" />
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
      <TargetGroupDetailView
        entity={entity}
        entityId={entityId}
        data={data}
        config={config}
        session={session}
        onRefresh={onRefresh}
        loading={detailState.loading}
        loadError={detailState.error}
      />
    );
  }

  if (!entityId || !entity) {
    return (
      <div className="content">
        <PageHeader route={route} eyebrow="Detail surface" />
        <EmptyState
          icon={Target}
          title="No entity selected."
          body="Open a list row with ?id= or seed workspace data so this detail route can resolve a record."
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
        onRefresh={onRefresh}
        runEvents={runEvents}
        loading={detailState.loading}
        loadError={detailState.error}
      />
    );
  }

  if (route === 'agent-detail') {
    return (
      <AgentDetailView
        entity={entity}
        entityId={entityId}
        data={data}
        config={config}
        session={session}
        onRefresh={onRefresh}
      />
    );
  }

  const tabOptions = [
    { id: 'overview', label: 'Overview' },
    { id: 'timeline', label: 'Timeline' },
    { id: 'related', label: 'Related evidence' },
    { id: 'actions', label: 'Actions' }
  ];

  return (
    <div className="content">
      <PageHeader route={route} eyebrow="Entity detail" />
      {(message || error || detailState.error || cveAuxError || detailState.loading || cveAuxLoading) && (
        <div className={error || detailState.error || cveAuxError ? 'form-banner error' : 'form-banner'}>
          {error || detailState.error || cveAuxError || message || (cveAuxLoading ? 'Loading CVE playbook and matches...' : 'Loading entity detail...')}
        </div>
      )}
      <Tabs value={tab} options={tabOptions} onChange={setTab} className="tabs-wrap" />
      {tab === 'overview' ? <div className="detail-layout">
        <Card>
          <CardHeader>
            <CardTitle>{getString(entity, ['name', 'hostname', 'canonical_url', 'cve_id', 'organization_name', 'id'], ROUTE_BY_ID.get(route)?.label)}</CardTitle>
            <CardDescription>
              <code>{entityId}</code> · {factors.length > 0 ? 'evidence-backed detail from tenant APIs' : 'entity detail with list fallback until API factors are available'}
            </CardDescription>
          </CardHeader>
          <CardContent className="kv-list">
            <div><span>Route</span><strong>{ROUTE_BY_ID.get(route)?.label}</strong></div>
            <div><span>Status</span><strong>{getString(entity, ['status', 'state', 'lifecycle_state', 'stage'], 'recorded')}</strong></div>
            <div><span>Updated</span><strong>{formatDate(entity.updated_at ?? entity.created_at)}</strong></div>
          </CardContent>
        </Card>
        <Card className="detail-primary">
          <CardHeader>
            <CardTitle>{factorsTitle}</CardTitle>
            <CardDescription>{factorsDescription}</CardDescription>
          </CardHeader>
          <CardContent>
            <FactorPanel factors={factors} emptyTitle={factorsEmptyTitle} emptyBody={factorsEmptyBody} />
          </CardContent>
        </Card>
      </div> : null}
      {tab === 'timeline' ? (
        <Card>
          <CardHeader>
            <CardTitle>Timeline</CardTitle>
            <CardDescription>Recorded milestones for this entity.</CardDescription>
          </CardHeader>
          <CardContent>
            <TimelinePanel items={timeline} />
          </CardContent>
        </Card>
      ) : null}
      {tab === 'related' ? (
        <div className="split">
          <Card>
            <CardHeader>
              <CardTitle>Related evidence</CardTitle>
              <CardDescription>Live counts and links from the current workspace payload.</CardDescription>
            </CardHeader>
            <CardContent className="kv-list">
              <div><span>Runs</span><strong>{relatedRuns.length}</strong></div>
              <div><span>Findings</span><strong>{relatedFindings.length}</strong></div>
              <div><span>Agents</span><strong>{relatedAgents.length}</strong></div>
              <div><span>Evidence</span><strong>{relatedEvidence.length}</strong></div>
              <div><span>Targets</span><strong>{targets.length}</strong></div>
            </CardContent>
          </Card>
          <Card>
            <CardHeader>
              <CardTitle>Linked records</CardTitle>
              <CardDescription>Open related runs, findings, and agents.</CardDescription>
            </CardHeader>
            <CardContent className="row-actions">
              {relatedRuns.slice(0, 4).map((run) => (
                <AnchorButton key={getString(run, ['id'], '')} size="sm" variant="secondary" href={buildDetailHref('run-detail', getString(run, ['id'], ''))}>
                  Run {getString(run, ['id'], '')}
                </AnchorButton>
              ))}
              {relatedAgents.slice(0, 3).map((agent) => (
                <AnchorButton key={getString(agent, ['id'], '')} size="sm" variant="ghost" href={buildDetailHref('agent-detail', getString(agent, ['id'], ''))}>
                  Agent {getString(agent, ['hostname', 'id'], '')}
                </AnchorButton>
              ))}
              <AnchorButton size="sm" variant="ghost" href="#findings">Open findings</AnchorButton>
              <AnchorButton size="sm" variant="ghost" href="#evidence">Open evidence</AnchorButton>
            </CardContent>
          </Card>
        </div>
      ) : null}
      {tab === 'actions' ? (
        <Card>
          <CardHeader>
            <CardTitle>Entity actions</CardTitle>
            <CardDescription>Route-specific mutations backed by tenant APIs.</CardDescription>
          </CardHeader>
          <CardContent className="row-actions">
            {route === 'waf-asset-detail' ? (
              <>
                <Button
                  size="sm"
                  variant="secondary"
                  disabled={busy !== ''}
                  onClick={() => void runDetailAction(`waf-validate-${entityId}`, () => requestJson(config, session, '/v1/waf/validations', {
                    method: 'POST',
                    body: { waf_asset_id: entityId, modes: ['marker'] }
                  }), 'Safe WAF validation started.')}
                >
                  Run validation
                </Button>
                <Button
                  size="sm"
                  variant="ghost"
                  disabled={busy !== ''}
                  onClick={() => void runDetailAction(`waf-exception-${entityId}`, () => requestJson(config, session, `/v1/waf/assets/${encodeURIComponent(entityId)}/exception`, {
                    method: 'POST',
                    body: {
                      owner: 'edge-team',
                      reason: 'approved_scope_exception',
                      expires_at: new Date(Date.now() + 90 * 24 * 60 * 60 * 1000).toISOString()
                    }
                  }), 'WAF exception recorded.')}
                >
                  Create exception
                </Button>
                <AnchorButton size="sm" variant="ghost" href="#waf-posture">Open WAF posture</AnchorButton>
              </>
            ) : null}
            {route === 'cve-detail' ? (
              <>
                <Button size="sm" variant="secondary" disabled={busy !== ''} onClick={() => void runDetailAction(`cve-triage-${entityId}`, () => requestJson(config, session, `/v1/waf/cve-pipeline/${encodeURIComponent(entityId)}/triage`, { method: 'POST', body: {} }), 'CVE item triaged.')}>Run triage</Button>
                <Button size="sm" variant="ghost" disabled={busy !== ''} onClick={() => void runDetailAction(`cve-validate-${entityId}`, () => requestJson(config, session, `/v1/waf/cve-pipeline/${encodeURIComponent(entityId)}/validate`, { method: 'POST' }), 'Safe validation delegated.')}>Validate exposure</Button>
                <AnchorButton size="sm" variant="ghost" href="#cve-pipeline">Open CVE pipeline</AnchorButton>
              </>
            ) : null}
            {route === 'supply-chain-detail' ? (
              <>
                <Button size="sm" variant="secondary" disabled={busy !== ''} onClick={() => void runDetailAction(`supply-state-${entityId}`, () => requestJson(config, session, `/v1/waf/supply-chain/risks/${encodeURIComponent(entityId)}/state`, { method: 'PATCH', body: { state: 'confirmed' } }), 'Risk state updated.')}>Confirm risk</Button>
                <form
                  className="product-form compact"
                  onSubmit={(event) => {
                    event.preventDefault();
                    const form = new FormData(event.currentTarget);
                    const targetPhase = String(form.get('target_phase') ?? 'AP2_manual_custody').trim();
                    void runDetailAction(`supply-phase-${entityId}`, () => requestJson(config, session, `/v1/waf/supply-chain/risks/${encodeURIComponent(entityId)}/phase-authorization`, {
                      method: 'POST',
                      body: {
                        target_phase: targetPhase,
                        customer_approval_reference: String(form.get('customer_approval_reference') ?? '').trim(),
                        customer_signed_at: new Date().toISOString(),
                        custody_ids: [String(form.get('custody_id') ?? `custody_${entityId}`).trim()],
                        manual_workflow_owner: String(form.get('manual_workflow_owner') ?? 'supply-chain-owner').trim()
                      }
                    }), 'Phase authorization recorded.');
                  }}
                >
                  <label><span>Target phase</span>
                    <select name="target_phase" defaultValue="AP2_manual_custody">
                      <option value="AP2_manual_custody">AP2 manual custody</option>
                      <option value="AP3_governed_active">AP3 governed active</option>
                    </select>
                  </label>
                  <label><span>Approval reference</span><input name="customer_approval_reference" placeholder="ticket-123" required /></label>
                  <label><span>Custody ID</span><input name="custody_id" placeholder={`custody_${entityId}`} required /></label>
                  <label><span>Workflow owner</span><input name="manual_workflow_owner" defaultValue="supply-chain-owner" required /></label>
                  <div className="form-actions"><Button size="sm" type="submit" disabled={busy !== ''}>Authorize phase</Button></div>
                </form>
                <AnchorButton size="sm" variant="ghost" href="#supply-chain">Open supply chain</AnchorButton>
              </>
            ) : null}
            {route === 'discovery-entity' ? <AnchorButton size="sm" variant="secondary" href="#discovery">Open discovery</AnchorButton> : null}

          </CardContent>
        </Card>
      ) : null}
      {tab === 'overview' && route === 'waf-asset-detail' && (
        <Card>
          <CardHeader>
            <CardTitle>WAF effectiveness</CardTitle>
            <CardDescription>Asset posture from `/v1/waf/assets/:id`.</CardDescription>
          </CardHeader>
          <CardContent className="kv-list">
            <div><span>Vendor</span><strong>{getString(entity, ['detected_vendor', 'expected_vendor_hint'])}</strong></div>
            <div><span>Criticality</span><strong>{getString(entity, ['business_criticality', 'criticality'])}</strong></div>
            <div><span>Control bypass</span><strong>{getNestedString(entity, ['effectiveness', 'control_bypass_status'], getString(entity, ['control_bypass_status'], 'unknown'))}</strong></div>
            <div><span>Pass rate</span><strong>{Math.round(getNestedNumber(entity, ['effectiveness', 'scenario_pass_rate'], getNestedNumber(entity, ['scenario_pass_rate'], 0)))}%</strong></div>
          </CardContent>
        </Card>
      )}
      {tab === 'overview' && route === 'cve-detail' && (
        <>
          <div className="split">
            <Card>
              <CardHeader>
                <CardTitle>CVE detail</CardTitle>
                <CardDescription>Metadata-only triage and mitigation workflow for one pipeline item.</CardDescription>
              </CardHeader>
              <CardContent className="kv-list">
                <div><span>CVE ID</span><strong>{getString(entity, ['cve_id', 'id'])}</strong></div>
                <div><span>Severity</span><strong>{getString(entity, ['severity'])}</strong></div>
                <div><span>Stage</span><strong>{getString(entity, ['stage'], 'ingest')}</strong></div>
                <div><span>Known exploited</span><strong>{entity?.known_exploited === true ? 'yes' : 'no'}</strong></div>
                <div><span>Triage summary</span><strong>{getNestedString(entity, ['triage_result', 'summary'], 'Run triage to populate factors.')}</strong></div>
              </CardContent>
            </Card>
            <Card>
              <CardHeader>
                <CardTitle>Asset matches</CardTitle>
                <CardDescription>Declared asset correlation from `/v1/waf/cve-pipeline/:id/match`.</CardDescription>
              </CardHeader>
              <CardContent>
                {cveAuxLoading ? <p className="muted">Loading asset matches…</p> : null}
                {!cveAuxLoading && cveMatches.length === 0 ? <p className="muted">No asset matches yet. Run triage and match from the actions tab.</p> : null}
                {cveMatches.length > 0 ? (
                  <div className="kv-list">
                    {cveMatches.slice(0, 6).map((match, index) => (
                      <div key={getString(match, ['asset_id', 'waf_asset_id'], String(index))}>
                        <span>{getString(match, ['asset_display', 'asset_id'], `match-${index + 1}`)}</span>
                        <strong>{getString(match, ['match_source'], 'declared')}</strong>
                      </div>
                    ))}
                  </div>
                ) : null}
              </CardContent>
            </Card>
          </div>
          {cvePlaybook ? (
            <Card>
              <CardHeader>
                <CardTitle>Mitigation playbook</CardTitle>
                <CardDescription>Grouped vendor slices from `/v1/waf/cve-pipeline/:id/playbook`.</CardDescription>
              </CardHeader>
              <CardContent className="kv-list">
                <div><span>Status</span><strong>{getString(cvePlaybook, ['status'], 'draft')}</strong></div>
                <div><span>CVE</span><strong>{getString(cvePlaybook, ['cve_id'], getString(entity, ['cve_id']))}</strong></div>
                <div><span>Vendor slices</span><strong>{getNestedArray(cvePlaybook, ['vendor_slices']).length}</strong></div>
                {getNestedArray(cvePlaybook, ['vendor_slices']).slice(0, 4).map((slice, index) => (
                  <div key={getString(slice, ['vendor'], String(index))}>
                    <span>{getString(slice, ['vendor'], `vendor-${index + 1}`)}</span>
                    <strong>{getString(slice, ['status'], 'draft')}</strong>
                  </div>
                ))}
              </CardContent>
            </Card>
          ) : null}
        </>
      )}
      {tab === 'overview' && route === 'supply-chain-detail' && (
        <Card>
          <CardHeader>
            <CardTitle>Supply chain risk detail</CardTitle>
            <CardDescription>Evidence summary and remediation steps from `/v1/waf/supply-chain/risks/:id`.</CardDescription>
          </CardHeader>
          <CardContent className="kv-list">
            <div><span>Hostname</span><strong>{getString(entity, ['hostname', 'id'])}</strong></div>
            <div><span>Exposure type</span><strong>{getString(entity, ['exposure_type'])}</strong></div>
            <div><span>Severity</span><strong>{getString(entity, ['severity'])}</strong></div>
            <div><span>State</span><strong>{getString(entity, ['state'], 'suspected')}</strong></div>
            <div><span>Confidence</span><strong>{Math.round(getNestedNumber(entity, ['confidence'], 0) * 100)}%</strong></div>
            <div><span>Remediation steps</span><strong>{getNestedArray(entity, ['remediation_steps']).map((step) => (typeof step === 'string' ? step : getString(step, ['step', 'description']))).join(' · ') || 'No steps recorded.'}</strong></div>
          </CardContent>
        </Card>
      )}
      {tab === 'overview' && route === 'discovery-entity' && (
        <Card>
          <CardHeader>
            <CardTitle>Discovery decision trail</CardTitle>
            <CardDescription>Approval-gated candidate metadata only.</CardDescription>
          </CardHeader>
          <CardContent className="kv-list">
            <div><span>Entity type</span><strong>{getString(entity, ['entity_type', 'candidate_type', 'type'])}</strong></div>
            <div><span>Confidence</span><strong>{getString(entity, ['confidence', 'confidence_score'])}</strong></div>
            <div><span>State</span><strong>{getString(entity, ['state'])}</strong></div>
            <div><span>Source</span><strong>{getString(entity, ['source_type', 'source_summary'], 'declared')}</strong></div>
          </CardContent>
        </Card>
      )}

    </div>
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
  const [busy, setBusy] = useState('');
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');
  const [preview, setPreview] = useState<ReportExportPreview | null>(null);
  const [previewLoading, setPreviewLoading] = useState(false);
  const previewLockedRef = useRef(false);
  const entityId = useMemo(() => {
    const fallback = getString(data.reports[0] ?? null, ['id'], '');
    return getRouteEntityId(fallback);
  }, [data.reports]);
  const reportFallback = data.reports.find((item) => getString(item, ['id'], '') === entityId) ?? null;
  const reportDetail = useEntityDetail(
    Boolean(entityId),
    config,
    session,
    `/v1/reports/${encodeURIComponent(entityId)}`,
    reportFallback
  );
  const report = reportDetail.detail;

  useEffect(() => {
    previewLockedRef.current = false;
  }, [entityId]);

  useEffect(() => {
    if (!entityId || !report) {
      setPreview(null);
      setPreviewLoading(false);
      return;
    }
    if (previewLockedRef.current) return;
    let cancelled = false;
    setPreviewLoading(true);
    setError('');
    async function loadCustodyPreview() {
      try {
        const headers = buildApiHeaders(config, session);
        const response = await fetch(`/v1/reports/${encodeURIComponent(entityId)}/export?format=json`, { headers });
        if (!response.ok) {
          const payload = await response.json().catch(() => null);
          throw new Error(String(payload?.message ?? payload?.error ?? `Export returned ${response.status}`));
        }
        const exported = await response.json();
        const custody = getNestedItem(exported, ['custody']);
        const payload = getNestedItem(exported, ['payload']);
        let verification: DataItem | null = null;
        if (custody && payload) {
          const verified = await requestJson(config, session, '/v1/custody/verify', {
            method: 'POST',
            body: { payload, custody }
          });
          verification = getNestedItem(verified as DataItem, ['verification']) ?? verified as DataItem;
        }
        if (!cancelled) {
          setPreview({
            reportId: entityId,
            format: 'json',
            title: getNestedString(payload, ['title'], getString(report, ['title', 'id'], entityId)),
            contentSha256: getString(custody ?? {}, ['content_sha256'], ''),
            artifactId: getString(custody ?? {}, ['artifact_id'], ''),
            schemaVersion: getString(custody ?? {}, ['schema_version'], ''),
            verification
          });
        }
      } catch (err) {
        if (!cancelled) {
          setPreview(null);
          setError(err instanceof Error ? err.message : 'Could not load custody preview.');
        }
      } finally {
        if (!cancelled) setPreviewLoading(false);
      }
    }
    void loadCustodyPreview();
    return () => {
      cancelled = true;
    };
  }, [entityId, report, config, session]);

  async function runReportAction<T>(label: string, action: () => Promise<T>, success: string) {
    setBusy(label);
    setError('');
    setMessage('');
    try {
      const result = await action();
      setMessage(success);
      return result;
    } catch (err) {
      const payload = (err as Error & { payload?: unknown }).payload as { error?: string; message?: string } | undefined;
      setError(payload?.message ?? payload?.error ?? (err instanceof Error ? err.message : 'Report action failed.'));
      return null;
    } finally {
      setBusy('');
    }
  }

  async function exportReport(reportId: string, format: 'json' | 'markdown' | 'html') {
    if (!reportId) return;
    await runReportAction(`export-${reportId}-${format}`, async () => {
      const headers = buildApiHeaders(config, session);
      const response = await fetch(`/v1/reports/${encodeURIComponent(reportId)}/export?format=${format}`, { headers });
      const contentType = response.headers.get('content-type') ?? '';
      if (!response.ok) {
        const payload = await response.json().catch(() => null);
        throw new Error(String(payload?.message ?? payload?.error ?? `Export returned ${response.status}`));
      }
      if (format === 'json' || contentType.includes('application/json')) {
        const exported = await response.json();
        const custody = getNestedItem(exported, ['custody']);
        const payload = getNestedItem(exported, ['payload']);
        let verification: DataItem | null = null;
        if (custody && payload) {
          const verified = await requestJson(config, session, '/v1/custody/verify', {
            method: 'POST',
            body: { payload, custody }
          });
          verification = getNestedItem(verified as DataItem, ['verification']) ?? verified as DataItem;
        }
        previewLockedRef.current = true;
        setPreview({
          reportId,
          format,
          title: getNestedString(payload, ['title'], getString(report, ['title', 'id'], reportId)),
          contentSha256: getString(custody ?? {}, ['content_sha256'], ''),
          artifactId: getString(custody ?? {}, ['artifact_id'], ''),
          schemaVersion: getString(custody ?? {}, ['schema_version'], ''),
          verification
        });
        await onRefresh();
        return exported;
      }
      const textPayload = await response.text();
      previewLockedRef.current = true;
      setPreview({
        reportId,
        format,
        title: getString(report, ['title', 'id'], reportId),
        textPreview: textPayload.slice(0, 900)
      });
      await onRefresh();
      return textPayload;
    }, `Report exported as ${format}.`);
  }

  if (!entityId || !report) {
    return (
      <div className="content">
        <PageHeader route="report-detail" eyebrow="Report detail" />
        <EmptyState
          icon={FileText}
          title="No report selected."
          body="Open a report from the Reports list with ?id= or generate a report first."
          actionLabel="Open Reports"
          actionHref="#reports"
        />
      </div>
    );
  }

  const verificationOk = preview?.verification ? getString(preview.verification, ['ok'], '') : '';
  const readinessScore = getNestedNumber(report, ['summary', 'readiness_score'], 0);
  const openFindings = getNestedNumber(report, ['summary', 'open_findings'], 0);

  return (
    <div className="content">
      <PageHeader route="report-detail" eyebrow="Report detail" />
      {(message || error || reportDetail.error || reportDetail.loading || previewLoading) && (
        <div className={error || reportDetail.error ? 'form-banner error' : 'form-banner'}>
          {error || reportDetail.error || message || (reportDetail.loading ? 'Loading report detail...' : 'Loading custody preview...')}
        </div>
      )}
      <div className="detail-layout">
        <Card>
          <CardHeader>
            <CardTitle>{getString(report, ['title', 'id'], 'Report')}</CardTitle>
            <CardDescription>
              <code>{entityId}</code> · resolved from `/v1/reports` and `/v1/reports/:id`
            </CardDescription>
          </CardHeader>
          <CardContent className="kv-list">
            <div><span>Kind</span><strong>{getString(report, ['kind'])}</strong></div>
            <div><span>Created</span><strong>{formatDate(report.created_at)}</strong></div>
            <div><span>Status</span><strong>{getString(report, ['status'], 'ready')}</strong></div>
            <div><span>Readiness</span><strong>{readinessScore}%</strong></div>
            <div><span>Open findings</span><strong>{openFindings}</strong></div>
          </CardContent>
        </Card>
        <Card className="detail-primary">
          <CardHeader>
            <CardTitle>Custody preview</CardTitle>
            <CardDescription>JSON export digest metadata verified through `/v1/custody/verify`.</CardDescription>
          </CardHeader>
          <CardContent className={preview?.contentSha256 || preview?.textPreview ? 'kv-list' : ''}>
            {!preview && !previewLoading ? (
              <EmptyState icon={FileCheck2} title="Custody preview unavailable." body="Export JSON to inspect custody metadata for this report." />
            ) : preview?.contentSha256 ? (
              <>
                <div><span>Artifact</span><strong>{preview.artifactId}</strong></div>
                <div><span>content_sha256</span><strong>{preview.contentSha256}</strong></div>
                <div><span>Schema</span><strong>{preview.schemaVersion}</strong></div>
                <div><span>Verification</span><strong>{verificationOk || 'verified'}</strong></div>
              </>
            ) : preview?.textPreview ? (
              <pre className="codeblock">{preview.textPreview}</pre>
            ) : (
              <p className="muted">Loading custody preview...</p>
            )}
          </CardContent>
        </Card>
      </div>
      <Card>
        <CardHeader>
          <CardTitle>Export formats</CardTitle>
          <CardDescription>Exports call `/v1/reports/:id/export`; JSON exports include custody manifests for verification.</CardDescription>
        </CardHeader>
        <CardContent className="stack-tight">
          <div className="row-actions">
            <Button size="sm" variant="secondary" disabled={busy !== ''} onClick={() => void exportReport(entityId, 'json')}>Export JSON</Button>
            <Button size="sm" variant="secondary" disabled={busy !== ''} onClick={() => void exportReport(entityId, 'markdown')}>Export Markdown</Button>
            <Button size="sm" variant="secondary" disabled={busy !== ''} onClick={() => void exportReport(entityId, 'html')}>Export HTML</Button>
            <AnchorButton size="sm" variant="ghost" href="#reports">Back to reports</AnchorButton>
          </div>
          {/*
            PDF export is intentionally out of scope for this slice: backend `src/services/reports.mjs`
            supports json|markdown|html only. Immutable PDF rendering and signing remain a release-gate boundary.
          */}
          <p className="muted">PDF export is not available in this slice; backend report exports support JSON, Markdown, and HTML only.</p>
        </CardContent>
      </Card>
    </div>
  );
}