import { useEffect, useMemo, useState, type FormEvent } from 'react';
import {
  Activity,
  Bot,
  CheckCircle2,
  ClipboardList,
  Clock3,
  FileCheck2,
  KeyRound,
  ListChecks,
  Network,
  RadioTower,
  ScanSearch,
  ShieldCheck,
  Siren,
  Target,
  TriangleAlert
} from 'lucide-react';
import { Badge } from '../components/ui/badge';
import { AnchorButton, Button } from '../components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../components/ui/card';
import { EmptyState } from '../components/ui/empty-state';
import { Progress } from '../components/ui/progress';
import { DataTable, type TableColumn } from '../components/ui/table';
import { Tabs } from '../components/ui/tabs';
import { FindingExplanationPanel } from '../components/findings/finding-explanation-panel';
import { buildEvidenceCustodyManifest } from '../lib/custody';
import { buildEvidenceChainExport, summarizeEvidenceExport } from '../lib/evidence-export';
import {
  computeFindingKpis,
  filterFindingsByTab,
  findingSlaDueAt,
  groupFindingsByTargetGroup,
  groupFindingsByVector,
  isFindingSlaBreach,
  resolveFindingRetestAction,
  type FindingTabId
} from '../lib/findings-helpers';
import {
  agentHeartbeatFreshness,
  agentInstallApiBase,
  filterAgentAuditEntries,
  formatAgentCapabilities,
  formatAgentHealth,
  formatAgentPlacement,
  placementFactorScore
} from '../lib/agent-helpers';
import {
  CHECK_SAFETY_SCOPE_TABS,
  countChecksBySafetyScope,
  filterChecksCatalog,
  type CheckFamilyTabId,
  type CheckSafetyScopeId
} from '../lib/checks-helpers';
import { extractPlacementDiagnosticsFromReadiness } from '../lib/onboarding';
import { requestJson } from '../lib/api';
import { ROUTE_BY_ID } from '../lib/navigation';
import { routeTabs } from '../lib/prototype-manifest';
import { buildDetailHref } from '../lib/route-params';
import type { DataItem, PortalConfig, PortalData, RouteId, Session } from '../lib/types';
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
  roadmapTotalItems,
  type WafPostureTabId
} from '../lib/waf-helpers';
import { formatDate, scoreTone } from '../lib/utils';
import { RunProofPanels, RunTimelineViz, TruthTablePanel, VerdictExplanationPanel } from '../components/runs/run-proof-panels';
import { DefensiveRulesPanel, MetricCard, PageHeader } from './page-components';

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
  l7: 'L7/API',
  waf: 'WAF',
  tls: 'TLS',
  protocol: 'Protocol',
  operations: 'Operations',
  high_scale: 'High-scale'
};

function formatVectorFamilyLabel(family: string) {
  return VECTOR_FAMILY_LABELS[family] ?? family.replace(/_/g, ' ');
}

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
    const payload = (err as Error & { payload?: unknown }).payload as { error?: string; message?: string } | undefined;
    setError(payload?.message ?? payload?.error ?? (err instanceof Error ? err.message : 'Action failed.'));
    return null;
  } finally {
    setBusy('');
  }
}

export function AgentsPage({
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
  const [tokenSecret, setTokenSecret] = useState('');
  const [agentTab, setAgentTab] = useState('fleet');
  const [installPlatform, setInstallPlatform] = useState('linux');
  const [placementReviews, setPlacementReviews] = useState<DataItem | null>(null);
  const [updateReleases, setUpdateReleases] = useState<DataItem[]>([]);
  const [trustKeys, setTrustKeys] = useState<DataItem[]>([]);
  const [auxLoading, setAuxLoading] = useState(false);
  const onlineAgents = data.agents.filter((agent) => getString(agent, ['status']) === 'online').length;
  const firstGroup = data.targetGroups[0] ?? null;
  const agentTabOptions = routeTabs('agents').map((tab) => ({ id: tab.id, label: tab.label }));
  const placementScore = placementFactorScore(data.state as DataItem | null);
  const placementSummary = getNestedItem(placementReviews, ['summary']);
  const readinessPlacement = extractPlacementDiagnosticsFromReadiness(data.state?.readiness as DataItem | undefined);
  const placementReviewRows = Array.isArray(placementReviews?.reviews) ? placementReviews.reviews as DataItem[] : [];
  const agentAuditEntries = filterAgentAuditEntries(data.audit);

  const fleetColumns: TableColumn<DataItem>[] = [
    { key: 'id', label: 'ID', render: (item) => <code>{getString(item, ['id'])}</code> },
    {
      key: 'health',
      label: 'Health',
      render: (item) => {
        const health = formatAgentHealth(item);
        const tone = health === 'online' ? 'success' : health === 'revoked' ? 'danger' : 'muted';
        return <Badge tone={tone}>{health}</Badge>;
      }
    },
    { key: 'version', label: 'Version', render: (item) => getString(item, ['version', 'agent_version'], '—') },
    { key: 'placement', label: 'Placement', render: (item) => formatAgentPlacement(item) },
    { key: 'last_heartbeat', label: 'Last heartbeat', render: (item) => formatDate(item.last_heartbeat_at) },
    {
      key: 'actions',
      label: 'Actions',
      render: (item) => {
        const id = getString(item, ['id'], '');
        const revoked = getString(item, ['status']) === 'revoked';
        return (
          <div className="row-actions">
            <AnchorButton size="sm" variant="secondary" href={buildDetailHref('agent-detail', id)}>Detail</AnchorButton>
            {!revoked ? <Button size="sm" variant="danger" disabled={busy !== ''} onClick={() => void revokeAgent(id)}>Revoke</Button> : null}
          </div>
        );
      }
    }
  ];

  const healthColumns: TableColumn<DataItem>[] = [
    { key: 'name', label: 'Agent', render: (item) => getString(item, ['hostname', 'name', 'id']) },
    { key: 'status', label: 'Status', render: (item) => <Badge tone={getString(item, ['status']) === 'online' ? 'success' : 'muted'}>{getString(item, ['status'], 'unknown')}</Badge> },
    { key: 'freshness', label: 'Heartbeat freshness', render: (item) => agentHeartbeatFreshness(item) },
    { key: 'heartbeat', label: 'Last heartbeat', render: (item) => formatDate(item.last_heartbeat_at) },
    { key: 'version', label: 'Version', render: (item) => getString(item, ['version'], '—') },
    { key: 'fingerprint', label: 'Gateway fingerprint', render: (item) => getString(item, ['fingerprint'], 'not registered') }
  ];

  const capabilityColumns: TableColumn<DataItem>[] = [
    { key: 'name', label: 'Agent', render: (item) => getString(item, ['hostname', 'name', 'id']) },
    { key: 'capabilities', label: 'Observation modes', render: (item) => formatAgentCapabilities(item) },
    { key: 'environment', label: 'Environment', render: (item) => getString(item, ['environment_id'], 'tenant scope') },
    { key: 'group', label: 'Target group', render: (item) => getString(item, ['target_group_id'], 'unbound') }
  ];

  const releaseColumns: TableColumn<DataItem>[] = [
    { key: 'version', label: 'Version', render: (item) => getString(item, ['version']) },
    { key: 'channel', label: 'Channel', render: (item) => getString(item, ['channel'], 'stable') },
    { key: 'state', label: 'State', render: (item) => <Badge tone="info">{getString(item, ['state'], 'active')}</Badge> },
    { key: 'rollout', label: 'Rollout', render: (item) => `${getNestedNumber(item, ['rollout', 'percentage'], 100)}%` },
    { key: 'created', label: 'Created', render: (item) => formatDate(item.created_at) },
    {
      key: 'actions',
      label: 'Actions',
      render: (item) => {
        const id = getString(item, ['id'], '');
        const canRollback = Boolean(item.rollback) && getString(item, ['state']) !== 'rollback_requested';
        return canRollback ? (
          <Button size="sm" variant="secondary" disabled={busy !== ''} onClick={() => void requestReleaseRollback(id)}>Request rollback</Button>
        ) : <span className="muted">—</span>;
      }
    }
  ];

  const trustKeyColumns: TableColumn<DataItem>[] = [
    { key: 'name', label: 'Name', render: (item) => getString(item, ['name']) },
    { key: 'fingerprint', label: 'Fingerprint', render: (item) => <code>{getString(item, ['fingerprint_sha256'])}</code> },
    { key: 'status', label: 'Status', render: (item) => <Badge tone={getString(item, ['status']) === 'active' ? 'success' : 'muted'}>{getString(item, ['status'])}</Badge> },
    { key: 'created', label: 'Created', render: (item) => formatDate(item.created_at) },
    {
      key: 'actions',
      label: 'Actions',
      render: (item) => {
        const id = getString(item, ['id'], '');
        const active = getString(item, ['status']) === 'active';
        return active ? (
          <Button size="sm" variant="danger" disabled={busy !== ''} onClick={() => void revokeTrustKey(id)}>Revoke</Button>
        ) : <span className="muted">revoked</span>;
      }
    }
  ];

  const logColumns: TableColumn<DataItem>[] = [
    { key: 'action', label: 'Action', render: (item) => getString(item, ['action']) },
    { key: 'resource', label: 'Resource', render: (item) => `${getString(item, ['resource_type'])}:${getString(item, ['resource_id'])}` },
    { key: 'actor', label: 'Actor', render: (item) => getString(item, ['actor_role'], 'system') },
    { key: 'when', label: 'Recorded', render: (item) => formatDate(item.created_at ?? item.timestamp) }
  ];

  useEffect(() => {
    if (!['placement', 'install', 'fleet'].includes(agentTab)) return undefined;
    let cancelled = false;
    setAuxLoading(true);
    requestJson(config, session, '/v1/placement/reviews')
      .then((payload) => {
        if (!cancelled) setPlacementReviews(payload as DataItem);
      })
      .catch(() => {
        if (!cancelled) setPlacementReviews(null);
      })
      .finally(() => {
        if (!cancelled) setAuxLoading(false);
      });
    return () => { cancelled = true; };
  }, [agentTab, config, session]);

  useEffect(() => {
    if (agentTab !== 'upgrades') return undefined;
    let cancelled = false;
    setAuxLoading(true);
    Promise.all([
      requestJson(config, session, '/v1/agent-updates'),
      requestJson(config, session, '/v1/agent-update-trust-keys')
    ])
      .then(([releasesPayload, trustPayload]) => {
        if (cancelled) return;
        const releases = Array.isArray((releasesPayload as { items?: unknown }).items)
          ? (releasesPayload as { items: DataItem[] }).items
          : [];
        const keys = Array.isArray((trustPayload as { items?: unknown }).items)
          ? (trustPayload as { items: DataItem[] }).items
          : [];
        setUpdateReleases(releases);
        setTrustKeys(keys);
      })
      .catch(() => {
        if (!cancelled) {
          setUpdateReleases([]);
          setTrustKeys([]);
        }
      })
      .finally(() => {
        if (!cancelled) setAuxLoading(false);
      });
    return () => { cancelled = true; };
  }, [agentTab, config, session]);

  async function createBootstrapToken() {
    const body: DataItem = {
      name: 'agent-install',
      expires_in_minutes: 60,
      max_registrations: 1
    };
    const environmentId = getString(firstGroup, ['environment_id'], '');
    const targetGroupId = getString(firstGroup, ['id'], '');
    if (environmentId) body.environment_id = environmentId;
    if (targetGroupId) body.target_group_id = targetGroupId;
    const created = await runAction(setBusy, setError, setMessage, 'create-bootstrap-token', () => requestJson(config, session, '/v1/bootstrap-tokens', {
      method: 'POST',
      body
    }), 'Bootstrap token created. Copy the one-time secret now.', onRefresh);
    const secret = getString(created as DataItem, ['secret'], getNestedString(created as DataItem, ['token', 'secret'], ''));
    if (secret) setTokenSecret(secret);
  }

  async function revokeAgent(id: string) {
    if (!id) return;
    await runAction(setBusy, setError, setMessage, `revoke-${id}`, () => requestJson(config, session, `/v1/agents/${id}/revoke`, { method: 'POST' }), 'Agent revoked. Heartbeat and jobs will be rejected.', onRefresh);
  }

  async function requestReleaseRollback(releaseId: string) {
    if (!releaseId) return;
    await runAction(setBusy, setError, setMessage, `rollback-${releaseId}`, () => requestJson(config, session, `/v1/agent-updates/${releaseId}/rollback`, { method: 'POST' }), 'Rollback requested for eligible agents.', async () => {
      const payload = await requestJson(config, session, '/v1/agent-updates') as { items?: DataItem[] };
      setUpdateReleases(Array.isArray(payload.items) ? payload.items : []);
      await onRefresh();
    });
  }

  async function revokeTrustKey(keyId: string) {
    if (!keyId) return;
    await runAction(setBusy, setError, setMessage, `trust-revoke-${keyId}`, () => requestJson(config, session, `/v1/agent-update-trust-keys/${keyId}/revoke`, { method: 'POST' }), 'Trust key revoked.', async () => {
      const payload = await requestJson(config, session, '/v1/agent-update-trust-keys') as { items?: DataItem[] };
      setTrustKeys(Array.isArray(payload.items) ? payload.items : []);
      await onRefresh();
    });
  }

  async function handleAddTrustKey(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    await runAction(setBusy, setError, setMessage, 'add-trust-key', () => requestJson(config, session, '/v1/agent-update-trust-keys', {
      method: 'POST',
      body: {
        name: String(form.get('name') ?? '').trim() || 'agent update signing key',
        public_key_der_base64: String(form.get('public_key_der_base64') ?? '').trim()
      }
    }), 'Trust key registered.', async () => {
      const payload = await requestJson(config, session, '/v1/agent-update-trust-keys') as { items?: DataItem[] };
      setTrustKeys(Array.isArray(payload.items) ? payload.items : []);
      event.currentTarget.reset();
      await onRefresh();
    });
  }

  const installToken = tokenSecret || '<BOOTSTRAP_TOKEN>';
  const apiBase = agentInstallApiBase();

  return (
    <div className="content">
      <PageHeader route="agents" />
      <div className="metric-grid three">
        <MetricCard label="Declared groups" value={data.targetGroups.length} sub="Manual or API import only" icon={Target} tone="info" />
        <MetricCard label="Agents" value={data.agents.length} sub="Outbound-only control channel" icon={Bot} tone="success" />
        <MetricCard label="Online agents" value={onlineAgents} sub="Current heartbeat status" icon={RadioTower} tone={onlineAgents > 0 ? 'success' : 'muted'} />
      </div>
      {(message || error) && <div className={error ? 'form-banner error' : 'form-banner'}>{error || message}</div>}
      <div className="row-actions" style={{ marginBottom: '0.75rem' }}>
        <Button disabled={busy !== ''} onClick={() => void createBootstrapToken()}>Create bootstrap token</Button>
      </div>
      <Tabs value={agentTab} options={agentTabOptions} onChange={setAgentTab} className="tabs-wrap" />
      {agentTab === 'install' ? (
        <div className="split">
          <Card>
            <CardHeader>
              <CardTitle>Install outbound agent</CardTitle>
              <CardDescription>Create a bootstrap token, then run the install command on your host. No inbound management port is required.</CardDescription>
            </CardHeader>
            <CardContent className="product-form">
              <Tabs
                value={installPlatform}
                options={[
                  { id: 'linux', label: 'Linux' },
                  { id: 'docker', label: 'Docker' },
                  { id: 'helm', label: 'Helm' }
                ]}
                onChange={setInstallPlatform}
                className="tabs-wrap"
              />
              {installPlatform === 'linux' ? (
                <pre className="codeblock">{`curl -fsSL ${apiBase}/agents/install.sh \\
  | sudo ASTRANULL_API_URL="${apiBase}" \\
       ASTRANULL_BOOTSTRAP_TOKEN="${installToken}" bash`}</pre>
              ) : null}
              {installPlatform === 'docker' ? (
                <pre className="codeblock">{`docker run -d --name astranull-agent \\
  -e ASTRANULL_API_URL="${apiBase}" \\
  -e ASTRANULL_BOOTSTRAP_TOKEN="${installToken}" \\
  astranull/agent:latest`}</pre>
              ) : null}
              {installPlatform === 'helm' ? (
                <pre className="codeblock">{`helm upgrade --install astranull-agent ./charts/agent \\
  --namespace astranull --create-namespace \\
  --set apiUrl="${apiBase}" \\
  --set bootstrapToken="${installToken}"`}</pre>
              ) : null}
              {tokenSecret ? <p className="muted">One-time token shown. It will not be displayed again after refresh.</p> : null}
            </CardContent>
          </Card>
          <Card>
            <CardHeader>
              <CardTitle>Placement diagnostics</CardTitle>
              <CardDescription>From <code>GET /v1/placement/reviews</code> and readiness placement factor.</CardDescription>
            </CardHeader>
            <CardContent className="kv-list">
              <div><span>Placement factor</span><strong>{placementScore != null ? `${placementScore}%` : 'Awaiting evidence'}</strong></div>
              <div><span>Online agents</span><strong>{onlineAgents}</strong></div>
              <div><span>Proven groups</span><strong>{getNestedNumber(placementSummary, ['proven'], getNumber(readinessPlacement ?? {}, ['proven'], 0))}</strong></div>
              <div><span>Misplaced risk</span><strong>{getNestedNumber(placementSummary, ['misplaced_risk'], getNumber(readinessPlacement ?? {}, ['misplaced_risk'], 0))}</strong></div>
            </CardContent>
          </Card>
        </div>
      ) : null}
      {agentTab === 'fleet' ? (
        <Card>
          <CardHeader>
            <CardTitle>Agent fleet</CardTitle>
            <CardDescription>Rows from <code>GET /v1/agents</code>. Revoke invalidates credentials immediately.</CardDescription>
          </CardHeader>
          <CardContent>
            <DataTable
              columns={fleetColumns}
              items={data.agents}
              empty={<EmptyState icon={Bot} title="No agents have registered yet." body="Create a bootstrap token on the Install tab, then install an outbound-only agent." />}
            />
          </CardContent>
        </Card>
      ) : null}
      {agentTab === 'health' ? (
        <Card>
          <CardHeader>
            <CardTitle>Agent health</CardTitle>
            <CardDescription>Heartbeat freshness and gateway trust metadata from <code>GET /v1/agents</code>.</CardDescription>
          </CardHeader>
          <CardContent>
            <DataTable
              columns={healthColumns}
              items={data.agents}
              empty={<EmptyState icon={Activity} title="No agents to monitor." body="Register an agent to see heartbeat freshness and version posture." />}
            />
          </CardContent>
        </Card>
      ) : null}
      {agentTab === 'placement' ? (
        <Card>
          <CardHeader>
            <CardTitle>Placement reviews</CardTitle>
            <CardDescription>Per target-group placement confidence from <code>GET /v1/placement/reviews</code>.</CardDescription>
          </CardHeader>
          <CardContent>
            {auxLoading ? <p className="muted">Loading placement reviews…</p> : null}
            {!auxLoading && placementReviewRows.length === 0 ? (
              <EmptyState icon={Target} title="No placement reviews yet." body="Declare target groups and register agents to compute placement confidence." />
            ) : null}
            {placementReviewRows.length > 0 ? (
              <div className="kv-list">
                {placementReviewRows.map((review) => (
                  <div key={getString(review, ['target_group_id'], getString(review, ['group_id']))}>
                    <span>{getString(review, ['target_group_name', 'target_group_id'], 'group')}</span>
                    <strong>{getString(review, ['status'], 'unknown')}</strong>
                  </div>
                ))}
              </div>
            ) : null}
            {placementSummary ? (
              <p className="muted">{getString(placementSummary, ['summary'], 'Placement diagnostics computed from declared scope and agent evidence.')}</p>
            ) : null}
          </CardContent>
        </Card>
      ) : null}
      {agentTab === 'capabilities' ? (
        <Card>
          <CardHeader>
            <CardTitle>Agent capabilities</CardTitle>
            <CardDescription>Observation modes reported on registration and heartbeat via <code>GET /v1/agents</code>.</CardDescription>
          </CardHeader>
          <CardContent>
            <DataTable
              columns={capabilityColumns}
              items={data.agents}
              empty={<EmptyState icon={ListChecks} title="No capability reports yet." body="Capabilities appear after the first agent heartbeat." />}
            />
          </CardContent>
        </Card>
      ) : null}
      {agentTab === 'logs' ? (
        <Card>
          <CardHeader>
            <CardTitle>Agent audit trail</CardTitle>
            <CardDescription>Metadata-only lifecycle events from <code>GET /v1/audit-log</code> (not host operational logs).</CardDescription>
          </CardHeader>
          <CardContent>
            <DataTable
              columns={logColumns}
              items={agentAuditEntries}
              empty={<EmptyState icon={ClipboardList} title="No agent audit events yet." body="Registration, heartbeat, revoke, and update actions appear here after agents connect." />}
            />
          </CardContent>
        </Card>
      ) : null}
      {agentTab === 'upgrades' ? (
        <div className="split">
          <Card>
            <CardHeader>
              <CardTitle>Release rollout</CardTitle>
              <CardDescription>Tenant releases from <code>GET /v1/agent-updates</code>. Agents poll <code>GET /v1/agents/:id/update</code>.</CardDescription>
            </CardHeader>
            <CardContent>
              {auxLoading ? <p className="muted">Loading releases…</p> : null}
              <DataTable
                columns={releaseColumns}
                items={updateReleases}
                empty={<EmptyState icon={Bot} title="No agent releases published." body="Release creation uses signed manifests and HTTPS distribution URLs via operator packaging workflows or POST /v1/agent-updates." />}
              />
            </CardContent>
          </Card>
          <Card>
            <CardHeader>
              <CardTitle>Trust keys</CardTitle>
              <CardDescription>Ed25519 signing keys from <code>GET /v1/agent-update-trust-keys</code>.</CardDescription>
            </CardHeader>
            <CardContent className="product-form">
              <DataTable
                columns={trustKeyColumns}
                items={trustKeys}
                empty={<EmptyState icon={KeyRound} title="No trust keys registered." body="Add the public key from your agent update signing ceremony." />}
              />
              <form className="product-form" onSubmit={(event) => void handleAddTrustKey(event)}>
                <label><span>Key name</span><input name="name" placeholder="production signing key" /></label>
                <label className="full"><span>Public key (DER base64)</span><textarea name="public_key_der_base64" rows={3} placeholder="MCowBQYDK2VwAyEA…" required /></label>
                <div className="form-actions full"><Button type="submit" disabled={busy !== ''}>Register trust key</Button></div>
              </form>
            </CardContent>
          </Card>
        </div>
      ) : null}
    </div>
  );
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
  onRefresh: () => Promise<void>;
}) {
  const [busy, setBusy] = useState('');
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');
  const [checkFilter, setCheckFilter] = useState<CheckFamilyTabId>('recommended');
  const [checkSafetyScope, setCheckSafetyScope] = useState<CheckSafetyScopeId>('all');
  const [selectedRunId, setSelectedRunId] = useState(() => getString(data.runs[0] ?? {}, ['id'], ''));
  const [runTab, setRunTab] = useState('summary');
  const [selectedFindingId, setSelectedFindingId] = useState(() => getString(data.findings[0] ?? {}, ['id'], ''));
  const [findingTab, setFindingTab] = useState<FindingTabId>('open');
  const [selectedEvidenceId, setSelectedEvidenceId] = useState(() => getString(data.evidence[0] ?? {}, ['id'], ''));
  const [runDetail, setRunDetail] = useState<DataItem | null>(null);
  const [runEvents, setRunEvents] = useState<DataItem[]>([]);
  const [findingDetail, setFindingDetail] = useState<DataItem | null>(null);
  const [evidenceDetail, setEvidenceDetail] = useState<DataItem | null>(null);
  const [exportOutput, setExportOutput] = useState('');
  const [evidenceCustodyPreview, setEvidenceCustodyPreview] = useState<DataItem | null>(null);

  const firstGroup = data.targetGroups[0] ?? null;
  const safeCheck = data.checks.find((check) => getString(check, ['safety_class']) === 'safe') ?? null;

  const checkSafetyCounts = useMemo(() => countChecksBySafetyScope(data.checks), [data.checks]);
  const filteredChecks = useMemo(
    () => filterChecksCatalog(data.checks, checkFilter, checkSafetyScope),
    [data.checks, checkFilter, checkSafetyScope]
  );

  useEffect(() => {
    if (!selectedRunId && data.runs[0]) setSelectedRunId(getString(data.runs[0], ['id'], ''));
  }, [data.runs, selectedRunId]);

  useEffect(() => {
    if (!selectedEvidenceId && data.evidence[0]) {
      setSelectedEvidenceId(getString(data.evidence[0], ['id'], ''));
    }
  }, [data.evidence, selectedEvidenceId]);

  useEffect(() => {
    if (!selectedFindingId && data.findings[0]) {
      setSelectedFindingId(getString(data.findings[0], ['id'], ''));
    }
  }, [data.findings, selectedFindingId]);

  useEffect(() => {
    setRunTab('summary');
  }, [selectedRunId]);

  useEffect(() => {
    if (route !== 'runs' || !selectedRunId) {
      setRunDetail(null);
      setRunEvents([]);
      return;
    }
    let cancelled = false;
    Promise.all([
      requestJson(config, session, `/v1/test-runs/${selectedRunId}`),
      requestJson(config, session, `/v1/test-runs/${selectedRunId}/events`)
    ])
      .then(([detail, eventsPayload]) => {
        if (cancelled) return;
        setRunDetail(detail as DataItem);
        const items = Array.isArray((eventsPayload as { items?: unknown }).items) ? (eventsPayload as { items: DataItem[] }).items : [];
        setRunEvents(items);
      })
      .catch(() => {
        if (!cancelled) {
          setRunDetail(null);
          setRunEvents([]);
        }
      });
    return () => { cancelled = true; };
  }, [route, selectedRunId, config, session, data.runs]);

  useEffect(() => {
    if (route !== 'findings' || !selectedFindingId) {
      setFindingDetail(null);
      return;
    }
    let cancelled = false;
    requestJson(config, session, `/v1/findings/${selectedFindingId}`)
      .then((payload) => { if (!cancelled) setFindingDetail(payload as DataItem); })
      .catch(() => { if (!cancelled) setFindingDetail(null); });
    return () => { cancelled = true; };
  }, [route, selectedFindingId, config, session]);

  useEffect(() => {
    if (route !== 'evidence' || !selectedEvidenceId) {
      setEvidenceDetail(null);
      return;
    }
    let cancelled = false;
    requestJson(config, session, `/v1/evidence/${selectedEvidenceId}`)
      .then((payload) => { if (!cancelled) setEvidenceDetail(payload as DataItem); })
      .catch(() => { if (!cancelled) setEvidenceDetail(null); });
    return () => { cancelled = true; };
  }, [route, selectedEvidenceId, config, session]);

  async function startSafeRun(checkId?: string) {
    const targetGroupId = getString(firstGroup, ['id'], '');
    const resolvedCheckId = checkId ?? getString(safeCheck ?? {}, ['check_id'], '');
    if (!targetGroupId || !resolvedCheckId) {
      setError('Declare a target group and safe check before starting a run.');
      return;
    }
    const detail = await requestJson(config, session, `/v1/target-groups/${targetGroupId}`) as DataItem;
    const targets = Array.isArray(detail.targets) ? detail.targets as DataItem[] : [];
    const targetId = getString(targets[0] ?? {}, ['id'], '');
    if (!targetId) {
      setError('Add at least one target to the declared group before starting a run.');
      return;
    }
    const created = await runAction(setBusy, setError, setMessage, 'start-safe-run', () => requestJson(config, session, '/v1/test-runs', {
      method: 'POST',
      body: { target_group_id: targetGroupId, target_id: targetId, check_id: resolvedCheckId }
    }), 'Safe validation run started.', onRefresh);
    if (created && typeof created === 'object') {
      const run = (created as { run?: DataItem }).run ?? created as DataItem;
      setSelectedRunId(getString(run, ['id'], ''));
    }
  }

  async function cancelRun(id: string) {
    if (!id) return;
    await runAction(setBusy, setError, setMessage, `cancel-${id}`, () => requestJson(config, session, `/v1/test-runs/${id}/cancel`, { method: 'POST' }), 'Run cancelled.', onRefresh);
  }

  async function finalizeRun(id: string) {
    if (!id) return;
    await runAction(setBusy, setError, setMessage, `finalize-${id}`, () => requestJson(config, session, `/v1/test-runs/${id}/finalize`, { method: 'POST' }), 'Run finalized after observation window.', onRefresh);
  }

  async function patchFinding(id: string, body: Record<string, unknown>, success: string) {
    if (!id) return;
    await runAction(setBusy, setError, setMessage, `finding-${id}`, () => requestJson(config, session, `/v1/findings/${id}`, { method: 'PATCH', body }), success, onRefresh);
  }

  async function retestFinding(finding: DataItem) {
    const findingId = getString(finding, ['id'], '');
    const retestAction = resolveFindingRetestAction(finding);
    if (!retestAction) {
      setError('Finding is missing retest context (check_id, waf asset, or CVE pipeline item).');
      return;
    }

    if (retestAction.kind === 'waf-validation') {
      await runAction(
        setBusy,
        setError,
        setMessage,
        `retest-waf-${findingId}`,
        () => requestJson(config, session, '/v1/waf/validations', {
          method: 'POST',
          body: { waf_asset_id: retestAction.wafAssetId, modes: ['marker'] }
        }),
        'WAF validation retest started.',
        onRefresh
      );
      return;
    }

    if (retestAction.kind === 'cve-retest') {
      await runAction(
        setBusy,
        setError,
        setMessage,
        `retest-cve-${findingId}`,
        () => requestJson(config, session, `/v1/waf/cve-pipeline/${encodeURIComponent(retestAction.pipelineId)}/retest`, {
          method: 'POST'
        }),
        'CVE pipeline retest started.',
        onRefresh
      );
      return;
    }

    if (retestAction.kind === 'cve-retest-url') {
      await runAction(
        setBusy,
        setError,
        setMessage,
        `retest-cve-url-${findingId}`,
        () => requestJson(config, session, retestAction.retestUrl, { method: 'POST' }),
        'CVE retest started.',
        onRefresh
      );
      return;
    }

    await startSafeRun(retestAction.checkId);
  }

  async function exportEvidenceChain() {
    if (!data.evidence.length) {
      setError('No evidence records available to export.');
      return;
    }
    setBusy('export-evidence-chain');
    setError('');
    setMessage('');
    try {
      const verdicts: DataItem[] = [];
      for (const run of data.runs.slice(-20)) {
        const runId = getString(run, ['id'], '');
        if (!runId) continue;
        try {
          const detail = await requestJson(config, session, `/v1/test-runs/${runId}`) as DataItem;
          const verdict = detail.verdict as DataItem | undefined;
          if (verdict) verdicts.push({ ...verdict, test_run_id: runId });
        } catch {
          /* partial chain */
        }
      }
      const exportData = buildEvidenceChainExport({
        evidence: data.evidence,
        runs: data.runs,
        verdicts,
        findings: data.findings
      });
      const custody = await buildEvidenceCustodyManifest(exportData.payload, session.tenant_id ?? 'ten_demo');
      const verified = await requestJson(config, session, '/v1/custody/verify', {
        method: 'POST',
        body: { payload: exportData.payload, custody }
      }) as DataItem;
      setExportOutput(exportData.json);
      setEvidenceCustodyPreview(getNestedItem(verified, ['verification']) ?? verified);
      setMessage('Evidence chain exported and custody digest verified.');
      await navigator.clipboard.writeText(exportData.json).catch(() => undefined);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Evidence chain export failed.');
      setEvidenceCustodyPreview(null);
    } finally {
      setBusy('');
    }
  }

  async function exportFinding(id: string) {
    if (!id) return;
    setBusy(`export-finding-${id}`);
    setError('');
    try {
      const payload = await requestJson(config, session, `/v1/findings/${id}/export`, { method: 'POST' });
      setExportOutput(JSON.stringify(payload, null, 2));
      setMessage('Finding export generated with custody manifest.');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Export failed.');
    } finally {
      setBusy('');
    }
  }

  if (route === 'checks') {
    const checkTabOptions = routeTabs('checks').map((tab) => ({ id: tab.id as CheckFamilyTabId, label: tab.label }));
    const safetyScopeOptions = CHECK_SAFETY_SCOPE_TABS.map((tab) => ({
      id: tab.id,
      label: `${tab.label} (${checkSafetyCounts[tab.id]})`
    }));
    const columns: TableColumn<DataItem>[] = [
      { key: 'check', label: 'Check', render: (item) => getString(item, ['name', 'check_id']) },
      {
        key: 'family',
        label: 'Family',
        render: (item) => <Badge tone="info">{formatVectorFamilyLabel(getString(item, ['vector_family']))}</Badge>
      },
      { key: 'safety', label: 'Safety', render: (item) => <Badge tone={getString(item, ['safety_class']) === 'safe' ? 'success' : 'warn'}>{getString(item, ['safety_class'])}</Badge> },
      { key: 'description', label: 'Description', render: (item) => getString(item, ['description']) },
      { key: 'probe', label: 'Probe profile', render: (item) => getString(item, ['probe_profile', 'kind']) }
    ];
    return (
      <div className="content">
        <PageHeader route="checks" />
        <div className="metric-grid three">
          <MetricCard label="Catalog checks" value={checkSafetyCounts.all} sub="Versioned catalog from API" icon={ListChecks} tone="info" />
          <MetricCard label="Safe checks" value={checkSafetyCounts.safe} sub="Customer-runnable" icon={ShieldCheck} tone="success" />
          <MetricCard label="SOC-only" value={checkSafetyCounts.soc} sub="Request via high-scale" icon={Siren} tone="muted" />
        </div>
        <Card>
          <CardHeader>
            <CardTitle>Check library</CardTitle>
            <CardDescription>Rows from `/v1/checks`. Use All/Safe/SOC scope tabs with family tabs below. SOC-gated checks remain request-only for customers.</CardDescription>
          </CardHeader>
          <CardContent>
            <Tabs value={checkSafetyScope} options={safetyScopeOptions} onChange={setCheckSafetyScope} className="tabs-wrap" />
            <Tabs value={checkFilter} options={checkTabOptions} onChange={setCheckFilter} className="tabs-wrap" />
            <DataTable
              columns={columns}
              items={filteredChecks}
              empty={checkFilter === 'custom' ? (
                <EmptyState icon={ListChecks} title="No custom checks in catalog." body="Customer-defined safe checks bind through test policies after staff-reviewed scope declaration." actionLabel="Open test policies" actionHref="#test-policies" />
              ) : (
                <EmptyState icon={ListChecks} title="No checks in this family." body="The check catalog loads from `/v1/checks` after tenant bootstrap." />
              )}
            />
          </CardContent>
        </Card>
      </div>
    );
  }

  if (route === 'runs') {
    const runColumns: TableColumn<DataItem>[] = [
      { key: 'id', label: 'Run', render: (item) => getString(item, ['id']) },
      { key: 'check', label: 'Check', render: (item) => getString(item, ['check_id']) },
      { key: 'status', label: 'Status', render: (item) => <Badge tone={getString(item, ['status']) === 'verdicted' ? 'success' : 'warn'}>{getString(item, ['status'])}</Badge> },
      { key: 'verdict', label: 'Verdict', render: (item) => getString(item, ['verdict', 'verdict'], 'pending') },
      { key: 'time', label: 'Started', render: (item) => formatDate(item.started_at ?? item.created_at) },
      {
        key: 'actions',
        label: 'Actions',
        render: (item) => {
          const id = getString(item, ['id'], '');
          const status = getString(item, ['status'], '');
          const cancellable = ['planned', 'running', 'collecting'].includes(status);
          return (
            <div className="row-actions">
              <Button size="sm" variant={id === selectedRunId ? 'default' : 'secondary'} onClick={() => setSelectedRunId(id)}>Detail</Button>
              <AnchorButton size="sm" variant="secondary" href={buildDetailHref('run-detail', id)}>Open</AnchorButton>
              {cancellable ? <Button size="sm" variant="danger" disabled={busy !== ''} onClick={() => void cancelRun(id)}>Cancel</Button> : null}
              {cancellable ? <Button size="sm" variant="ghost" disabled={busy !== ''} onClick={() => void finalizeRun(id)}>Finalize</Button> : null}
            </div>
          );
        }
      }
    ];
    const verdict = runDetail?.verdict as DataItem | undefined;
    const runTabOptions = routeTabs('runs').map((tab) => ({ id: tab.id, label: tab.label }));
    const probeEvents = runEvents.filter((event) => getString(event, ['signal_type']) === 'probe_result');
    const agentEvents = runEvents.filter((event) => ['agent_observation', 'agent_no_observation'].includes(getString(event, ['signal_type'])));
    const relatedEvidence = data.evidence.filter((item) => getString(item, ['test_run_id'], '') === selectedRunId);
    const relatedFindings = data.findings.filter((finding) => getString(finding, ['test_run_id'], '') === selectedRunId);
    return (
      <div className="content">
        <PageHeader route="runs" />
        {(message || error) && <div className={error ? 'form-banner error' : 'form-banner'}>{error || message}</div>}
        <Card>
          <CardHeader>
            <CardTitle>Start safe validation</CardTitle>
            <CardDescription>Creates a bounded run against the first declared target in the first active target group.</CardDescription>
          </CardHeader>
          <CardContent>
            <Button disabled={busy !== '' || !firstGroup || !safeCheck} onClick={() => void startSafeRun()}>{busy === 'start-safe-run' ? 'Starting...' : 'Start safe run'}</Button>
          </CardContent>
        </Card>
        <Card>
          <CardHeader><CardTitle>Test runs</CardTitle><CardDescription>From `/v1/test-runs` with live detail, events, cancel, and finalize.</CardDescription></CardHeader>
          <CardContent>
            <DataTable columns={runColumns} items={data.runs} empty={<EmptyState icon={Activity} title="No test runs yet." body="Start a safe validation run after declaring target scope." actionLabel="Open onboarding" actionHref="#onboarding" />} />
          </CardContent>
        </Card>
        {runDetail ? (
          <Card>
            <CardHeader>
              <CardTitle>Run detail</CardTitle>
              <CardDescription>
                {selectedRunId} · {getString(runDetail, ['check_id'])} · {getString(runDetail, ['status'])}
              </CardDescription>
            </CardHeader>
            <CardContent>
              <Tabs value={runTab} options={runTabOptions} onChange={setRunTab} className="tabs-wrap" />
              {runTab === 'summary' ? (
                <>
                  <div className="kv-list">
                    <div><span>Status</span><strong>{getString(runDetail, ['status'])}</strong></div>
                    <div><span>Check</span><strong>{getString(runDetail, ['check_id'])}</strong></div>
                    <div><span>Target group</span><strong>{getString(runDetail, ['target_group_id'])}</strong></div>
                    <div><span>Target</span><strong>{getString(runDetail, ['target_id'])}</strong></div>
                    <div><span>Vector</span><strong>{getString(runDetail, ['vector_family'], '—')}</strong></div>
                    <div><span>Safety</span><strong>{getString(runDetail, ['safety_class'], '—')}</strong></div>
                    <div><span>Verdict</span><strong>{getString(verdict ?? {}, ['verdict'], 'pending')}</strong></div>
                    <div><span>Placement confidence</span><strong>{getNestedString(verdict ?? {}, ['placement_confidence', 'level'], '—')}</strong></div>
                  </div>
                  <RunProofPanels detail={runDetail} events={runEvents} />
                  <div className="row-actions" style={{ marginTop: '1rem' }}>
                    <AnchorButton size="sm" variant="secondary" href={buildDetailHref('run-detail', selectedRunId)}>Open full detail</AnchorButton>
                  </div>
                </>
              ) : null}
              {runTab === 'timeline' ? (
                <>
                  <RunTimelineViz events={runEvents} />
                  {runEvents.length === 0 ? <p className="muted">No events recorded yet.</p> : (
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
                  )}
                </>
              ) : null}
              {runTab === 'probe-results' ? (
                probeEvents.length === 0 ? <p className="muted">No probe_result events for this run.</p> : (
                  <div className="kv-list">
                    {probeEvents.map((event, index) => (
                      <div key={getString(event, ['id'], String(index))}>
                        <span>{formatDate(event.timestamp ?? event.created_at)}</span>
                        <strong>{getNestedString(event, ['metadata', 'external_result'], getString(event, ['external_result'], getString(event, ['source'], 'probe_result')))}</strong>
                      </div>
                    ))}
                  </div>
                )
              ) : null}
              {runTab === 'agent-observations' ? (
                agentEvents.length === 0 ? <p className="muted">No agent observation events for this run.</p> : (
                  <div className="kv-list">
                    {agentEvents.map((event, index) => (
                      <div key={getString(event, ['id'], String(index))}>
                        <span>{getString(event, ['signal_type'])}</span>
                        <strong>{getString(event, ['agent_id'], getString(event, ['source'], 'agent'))} · {formatDate(event.timestamp ?? event.created_at)}</strong>
                      </div>
                    ))}
                  </div>
                )
              ) : null}
              {runTab === 'correlation' ? (
                <>
                  <VerdictExplanationPanel detail={runDetail} events={runEvents} />
                  <TruthTablePanel detail={runDetail} />
                </>
              ) : null}
              {runTab === 'evidence' ? (
                relatedEvidence.length === 0 ? <p className="muted">No evidence records linked to this run yet.</p> : (
                  <>
                    <div className="kv-list">
                      {relatedEvidence.map((item) => (
                        <div key={getString(item, ['id'], '')}>
                          <span>{getString(item, ['kind', 'signal_type'], 'evidence')}</span>
                          <strong>{getString(item, ['id'])}</strong>
                        </div>
                      ))}
                    </div>
                    {relatedFindings.length > 0 ? (
                      <div className="row-actions" style={{ marginTop: '1rem' }}>
                        <AnchorButton size="sm" variant="ghost" href="#findings">Open findings</AnchorButton>
                      </div>
                    ) : null}
                  </>
                )
              ) : null}
              {runTab === 'events' ? (
                runEvents.length === 0 ? <p className="muted">No events recorded yet.</p> : (
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
                )
              ) : null}
            </CardContent>
          </Card>
        ) : null}
      </div>
    );
  }

  if (route === 'findings') {
    const findingKpis = computeFindingKpis(data.findings);
    const findingTabOptions = routeTabs('findings').map((tab) => ({ id: tab.id as FindingTabId, label: tab.label }));
    const filteredFindings = filterFindingsByTab(data.findings, findingTab, data.checks);
    const groupedByTargetGroup = groupFindingsByTargetGroup(filteredFindings, data.targetGroups);
    const groupedByVector = groupFindingsByVector(filteredFindings, data.checks);

    const findingColumns: TableColumn<DataItem>[] = [
      { key: 'title', label: 'Finding', render: (item) => getString(item, ['title', 'id']) },
      { key: 'severity', label: 'Severity', render: (item) => <Badge tone={['critical', 'high'].includes(getString(item, ['severity']).toLowerCase()) ? 'danger' : 'warn'}>{getString(item, ['severity'])}</Badge> },
      { key: 'status', label: 'Status', render: (item) => getString(item, ['status']) },
      { key: 'assignee', label: 'Assignee', render: (item) => getString(item, ['assignee'], '—') },
      ...(findingTab === 'target-group' ? [{
        key: 'target-group',
        label: 'Target group',
        render: (item: DataItem) => getString(item, ['target_group_id'], '—')
      }] as TableColumn<DataItem>[] : []),
      ...(findingTab === 'vector' ? [{
        key: 'vector',
        label: 'Vector',
        render: (item: DataItem) => formatVectorFamilyLabel(getString(item, ['vector_family'], getString(
          data.checks.find((check) => getString(check, ['check_id']) === getString(item, ['check_id'], '')) ?? {},
          ['vector_family'],
          'other'
        )))
      }] as TableColumn<DataItem>[] : []),
      ...(findingTab === 'sla' ? [{
        key: 'sla',
        label: 'SLA',
        render: (item: DataItem) => {
          const dueAt = findingSlaDueAt(item);
          if (!dueAt) return '—';
          return (
            <Badge tone={isFindingSlaBreach(item) ? 'danger' : 'warn'}>
              Due {formatDate(dueAt)}
            </Badge>
          );
        }
      }] as TableColumn<DataItem>[] : []),
      { key: 'time', label: 'Updated', render: (item) => formatDate(item.updated_at ?? item.created_at) },
      {
        key: 'actions',
        label: 'Actions',
        render: (item) => {
          const id = getString(item, ['id'], '');
          return (
            <div className="row-actions">
              <Button size="sm" variant={id === selectedFindingId ? 'default' : 'secondary'} onClick={() => setSelectedFindingId(id)}>Detail</Button>
              <Button size="sm" variant="ghost" disabled={busy !== ''} onClick={() => void patchFinding(id, { status: 'accepted_risk' }, 'Finding marked accepted risk.')}>Accept risk</Button>
              <Button size="sm" variant="ghost" disabled={busy !== ''} onClick={() => void patchFinding(id, { status: 'closed' }, 'Finding closed.')}>Close</Button>
              <Button size="sm" variant="ghost" disabled={busy !== ''} onClick={() => void retestFinding(item)}>Retest</Button>
            </div>
          );
        }
      }
    ];

    const findingsEmpty = (
      <EmptyState
        icon={TriangleAlert}
        title={`No ${findingTabOptions.find((tab) => tab.id === findingTab)?.label.toLowerCase() ?? 'matching'} findings.`}
        body="Findings appear after failing verdicts are published and triaged."
      />
    );

    const renderFindingTable = (items: DataItem[]) => (
      <DataTable columns={findingColumns} items={items} empty={findingsEmpty} />
    );

    return (
      <div className="content">
        <PageHeader route="findings" />
        <div className="metric-grid">
          <MetricCard
            label="Open findings"
            value={findingKpis.openCount}
            sub={findingKpis.openSeverityBreakdown}
            icon={TriangleAlert}
            tone={findingKpis.openCount > 0 ? 'warn' : 'success'}
          />
          <MetricCard
            label="Accepted risk"
            value={findingKpis.acceptedRiskCount}
            sub="Owner-approved exceptions"
            icon={ShieldCheck}
            tone={findingKpis.acceptedRiskCount > 0 ? 'info' : 'muted'}
          />
          <MetricCard
            label="Closed (30d)"
            value={findingKpis.closed30dCount}
            sub="Resolved within the last 30 days"
            icon={CheckCircle2}
            tone={findingKpis.closed30dCount > 0 ? 'success' : 'muted'}
          />
          <MetricCard
            label="SLA breach"
            value={findingKpis.slaBreachCount}
            sub="Open findings past severity window"
            icon={Clock3}
            tone={findingKpis.slaBreachCount > 0 ? 'danger' : 'success'}
          />
        </div>
        {(message || error) && <div className={error ? 'form-banner error' : 'form-banner'}>{error || message}</div>}
        <Card>
          <CardHeader>
            <CardTitle>Findings</CardTitle>
            <CardDescription>Evidence-backed gaps from `/v1/findings` with triage tabs, assignee workflow, export, and retest actions.</CardDescription>
          </CardHeader>
          <CardContent>
            <Tabs value={findingTab} options={findingTabOptions} onChange={setFindingTab} className="tabs-wrap" />
            {findingTab === 'target-group' ? (
              groupedByTargetGroup.length === 0 ? findingsEmpty : (
                <div className="finding-group-sections">
                  {groupedByTargetGroup.map((group) => (
                    <section key={group.groupId} className="finding-group-section">
                      <div className="finding-group-header">
                        <h4>{group.label}</h4>
                        <Badge tone="info">{group.items.length} open</Badge>
                      </div>
                      {renderFindingTable(group.items)}
                    </section>
                  ))}
                </div>
              )
            ) : findingTab === 'vector' ? (
              groupedByVector.length === 0 ? findingsEmpty : (
                <div className="finding-group-sections">
                  {groupedByVector.map((group) => (
                    <section key={group.family} className="finding-group-section">
                      <div className="finding-group-header">
                        <h4>{group.label}</h4>
                        <Badge tone="info">{group.items.length} open</Badge>
                      </div>
                      {renderFindingTable(group.items)}
                    </section>
                  ))}
                </div>
              )
            ) : renderFindingTable(filteredFindings)}
          </CardContent>
        </Card>
        {findingDetail ? (
          <div className="split">
            <Card>
              <CardHeader>
                <CardTitle>Why this finding?</CardTitle>
                <CardDescription>
                  {getString(findingDetail, ['title'])} · {getString(findingDetail, ['severity'])} · {getString(findingDetail, ['status'])}
                </CardDescription>
              </CardHeader>
              <CardContent>
                <FindingExplanationPanel finding={findingDetail} config={config} session={session} />
              </CardContent>
            </Card>
            <Card>
              <CardHeader><CardTitle>Triage and assignee</CardTitle><CardDescription>Assign owner and export custody-backed evidence.</CardDescription></CardHeader>
              <CardContent>
                <form className="product-form" onSubmit={(event) => {
                  event.preventDefault();
                  const form = new FormData(event.currentTarget);
                  void patchFinding(selectedFindingId, {
                    assignee: String(form.get('assignee') ?? '').trim(),
                    notes: String(form.get('notes') ?? '').trim()
                  }, 'Triage notes updated.');
                }}>
                  <label className="full"><span>Assignee</span><input name="assignee" defaultValue={getString(findingDetail, ['assignee'], '')} /></label>
                  <label className="full"><span>Triage notes</span><textarea name="notes" rows={4} defaultValue={getString(findingDetail, ['notes'], '')} placeholder="Owner context, remediation plan, or accepted-risk rationale." /></label>
                  <div className="form-actions full"><Button type="submit" disabled={busy !== ''}>Save triage</Button></div>
                </form>
                <div className="row-actions">
                  <Button size="sm" variant="secondary" disabled={busy !== ''} onClick={() => void exportFinding(selectedFindingId)}>Export with custody</Button>
                  <Button size="sm" variant="ghost" disabled={busy !== ''} onClick={() => void retestFinding(findingDetail)}>Start retest run</Button>
                </div>
                {exportOutput ? <pre className="codeblock">{exportOutput}</pre> : null}
              </CardContent>
            </Card>
          </div>
        ) : data.findings.length > 0 ? (
          <Card>
            <CardHeader><CardTitle>Triage and assignee</CardTitle><CardDescription>Select a finding to assign an owner or export custody-backed evidence.</CardDescription></CardHeader>
          </Card>
        ) : null}
      </div>
    );
  }

  // evidence
  const evidenceColumns: TableColumn<DataItem>[] = [
    { key: 'id', label: 'Evidence', render: (item) => getString(item, ['id']) },
    { key: 'kind', label: 'Kind', render: (item) => getString(item, ['label', 'kind', 'signal_type']) },
    { key: 'run', label: 'Test run', render: (item) => getString(item, ['test_run_id']) },
    {
      key: 'source',
      label: 'Source',
      render: (item) => getString(item, ['source'], getNestedString(item, ['metadata', 'simulation'], getNestedString(item, ['metadata', 'vector_family'], '—')))
    },
    { key: 'time', label: 'Recorded', render: (item) => formatDate(item.created_at ?? item.timestamp) },
    {
      key: 'actions',
      label: 'Actions',
      render: (item) => {
        const id = getString(item, ['id'], '');
        return (
          <Button
            size="sm"
            variant={id === selectedEvidenceId ? 'default' : 'secondary'}
            onClick={() => setSelectedEvidenceId(id)}
          >
            Detail
          </Button>
        );
      }
    }
  ];

  const chainPreview = buildEvidenceChainExport({
    evidence: data.evidence,
    runs: data.runs,
    findings: data.findings
  });

  return (
    <div className="content">
      <PageHeader route="evidence" />
      {(message || error) && <div className={error ? 'form-banner error' : 'form-banner'}>{error || message}</div>}
      <div className="metric-grid three">
        <MetricCard label="Evidence records" value={data.evidence.length} sub="Custody-ready metadata" icon={FileCheck2} tone="info" />
        <MetricCard label="Linked runs" value={new Set(data.evidence.map((e) => getString(e, ['test_run_id'], '')).filter(Boolean)).size} sub="Distinct test runs" icon={Activity} tone="success" />
        <MetricCard label="Open findings" value={data.findings.filter((f) => getString(f, ['status']) === 'open').length} sub="Related posture gaps" icon={TriangleAlert} tone="warn" />
      </div>
      <Card>
        <CardHeader>
          <CardTitle>Evidence chain export</CardTitle>
          <CardDescription>Export correlated evidence, run, verdict, and finding links with custody verification through `/v1/custody/verify`.</CardDescription>
        </CardHeader>
        <CardContent className="product-form">
          <div className="row-actions">
            <Button disabled={busy !== '' || data.evidence.length === 0} onClick={() => void exportEvidenceChain()}>Export chain JSON</Button>
            <Button variant="secondary" disabled={!exportOutput} onClick={() => void navigator.clipboard.writeText(exportOutput)}>Copy export JSON</Button>
          </div>
          {data.evidence.length > 0 ? (
            <div className="kv-list">
              {summarizeEvidenceExport(chainPreview).map(([label, value]) => (
                <div key={label}><span>{label}</span><strong>{value}</strong></div>
              ))}
            </div>
          ) : null}
          {evidenceCustodyPreview ? (
            <div className="kv-list">
              <div><span>Custody status</span><strong>{evidenceCustodyPreview.ok === true ? 'Digest verified' : getString(evidenceCustodyPreview, ['error'], 'verification failed')}</strong></div>
              <div><span>Schema</span><strong>{getString(evidenceCustodyPreview, ['schema_version'])}</strong></div>
              <div><span>Digest</span><strong>{getString(evidenceCustodyPreview, ['content_sha256'], '—').slice(0, 16)}…</strong></div>
            </div>
          ) : <p className="muted">No raw payloads or secrets are rendered in custody previews.</p>}
        </CardContent>
      </Card>
      <Card>
        <CardHeader><CardTitle>Evidence vault</CardTitle><CardDescription>Metadata-only records from `/v1/evidence`.</CardDescription></CardHeader>
        <CardContent><DataTable columns={evidenceColumns} items={data.evidence} empty={<EmptyState icon={FileCheck2} title="No evidence yet." body="Evidence appears after probe and agent observations correlate." />} /></CardContent>
      </Card>
      {data.evidence.length > 0 ? (
        <Card>
          <CardHeader><CardTitle>Evidence chain</CardTitle><CardDescription>Correlated links between vault records, runs, and findings.</CardDescription></CardHeader>
          <CardContent>
            <ol className="dashboard-link-list">
              {chainPreview.payload.chain.slice(0, 12).map((link) => (
                <li key={String(link.evidence_id)}>
                  <div>
                    <strong>{String(link.evidence_id)}</strong>
                    <span>run {String(link.test_run_id ?? '—')} · verdict {String(link.verdict ?? 'pending')}</span>
                  </div>
                </li>
              ))}
            </ol>
          </CardContent>
        </Card>
      ) : null}
      {evidenceDetail ? (
        <Card>
          <CardHeader><CardTitle>Evidence detail</CardTitle><CardDescription>{selectedEvidenceId}</CardDescription></CardHeader>
          <CardContent className="kv-list">
            <div><span>Kind</span><strong>{getString(evidenceDetail, ['label', 'kind', 'signal_type'])}</strong></div>
            <div><span>Source</span><strong>{getString(evidenceDetail, ['source'], getNestedString(evidenceDetail, ['metadata', 'simulation'], getNestedString(evidenceDetail, ['metadata', 'vector_family'], '—')))}</strong></div>
            <div><span>Test run</span><strong>{getString(evidenceDetail, ['test_run_id'])}</strong></div>
            <div><span>Check</span><strong>{getString(evidenceDetail, ['check_id'])}</strong></div>
            <div><span>Created</span><strong>{formatDate(evidenceDetail.created_at)}</strong></div>
            <div><span>Metadata keys</span><strong>{Object.keys((evidenceDetail.metadata as object) ?? {}).join(', ') || 'none'}</strong></div>
          </CardContent>
        </Card>
      ) : null}
      {exportOutput ? <Card><CardHeader><CardTitle>Export preview</CardTitle></CardHeader><CardContent><pre className="codeblock">{exportOutput.slice(0, 2400)}{exportOutput.length > 2400 ? '\n…' : ''}</pre></CardContent></Card> : null}
    </div>
  );
}

export function PostureSurfacePage({
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
  const [busy, setBusy] = useState('');
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');
  const [output, setOutput] = useState('');
  const [deliverChannel, setDeliverChannel] = useState<string>('webhook');
  const [selectedActionItemId, setSelectedActionItemId] = useState('');
  const [importTargetGroupByCandidate, setImportTargetGroupByCandidate] = useState<Record<string, string>>({});
  const [approveTargetGroupByCandidate, setApproveTargetGroupByCandidate] = useState<Record<string, string>>({});
  const [wafAssetTargetGroupId, setWafAssetTargetGroupId] = useState(() => getString(data.targetGroups[0] ?? null, ['id'], ''));
  const [wafAssetTargets, setWafAssetTargets] = useState<DataItem[]>([]);
  const [wafAssetTargetsLoading, setWafAssetTargetsLoading] = useState(false);
  const [wafPostureTab, setWafPostureTab] = useState<WafPostureTabId>('overview');
  const [driftScanLatest, setDriftScanLatest] = useState<DataItem | null>(null);
  const [sessionRetestsByDrift, setSessionRetestsByDrift] = useState<Record<string, DataItem>>({});
  const [exceptionAssetId, setExceptionAssetId] = useState(() => getString(data.wafAssets[0] ?? {}, ['id'], ''));
  const wafEnabled = featureEnabled(data, 'waf_posture');
  const discoveryEnabled = featureEnabled(data, 'external_discovery');
  const requiresWaf = ['waf-posture', 'cve-pipeline', 'supply-chain', 'remediation'].includes(route);
  const enabled = route === 'discovery' ? discoveryEnabled : wafEnabled;
  const protectedPercent = getNestedNumber(data.wafCoverage, ['percentages', 'protected'], 0);
  const firstGroup = data.targetGroups[0] ?? null;
  const firstFindingId = getString(data.findings[0] ?? {}, ['id'], '');
  const defaultTargetGroupId = getString(firstGroup, ['id'], '');

  useEffect(() => {
    if (route !== 'waf-posture' || !wafAssetTargetGroupId) {
      setWafAssetTargets([]);
      return;
    }
    let cancelled = false;
    setWafAssetTargetsLoading(true);
    requestJson(config, session, `/v1/target-groups/${encodeURIComponent(wafAssetTargetGroupId)}`)
      .then((detail) => {
        if (cancelled) return;
        const targets = Array.isArray((detail as DataItem).targets) ? (detail as DataItem).targets as DataItem[] : [];
        setWafAssetTargets(targets);
      })
      .catch(() => {
        if (!cancelled) setWafAssetTargets([]);
      })
      .finally(() => {
        if (!cancelled) setWafAssetTargetsLoading(false);
      });
    return () => { cancelled = true; };
  }, [route, wafAssetTargetGroupId, config, session]);

  useEffect(() => {
    if (route !== 'waf-posture' || !wafEnabled) {
      setDriftScanLatest(null);
      return;
    }
    let cancelled = false;
    requestJson(config, session, '/v1/waf/drift-scans/latest')
      .then((payload) => {
        if (cancelled) return;
        const scan = (payload as { scan_result?: DataItem | null }).scan_result;
        setDriftScanLatest(scan && typeof scan === 'object' ? scan as DataItem : null);
      })
      .catch(() => {
        if (!cancelled) setDriftScanLatest(null);
      });
    return () => { cancelled = true; };
  }, [route, wafEnabled, config, session, data.wafDriftEvents.length]);

  useEffect(() => {
    if (!exceptionAssetId && data.wafAssets.length > 0) {
      setExceptionAssetId(getString(data.wafAssets[0] ?? {}, ['id'], ''));
    }
  }, [data.wafAssets, exceptionAssetId]);

  function resolveTargetGroupId(candidateId: string, pickerState: Record<string, string>) {
    return pickerState[candidateId] ?? defaultTargetGroupId;
  }

  async function handleAction(label: string, action: () => Promise<unknown>, success: string) {
    const result = await runAction(setBusy, setError, setMessage, label, action, success, onRefresh);
    if (result) setOutput(JSON.stringify(result, null, 2));
    return result;
  }

  const routeConfig: Record<string, {
    metricCards: Array<{ label: string; value: string | number; sub: string; icon: typeof Activity; tone: 'default' | 'success' | 'warn' | 'danger' | 'info' | 'muted' }>;
    columns: TableColumn<DataItem>[];
    items: DataItem[];
    emptyTitle: string;
    emptyBody: string;
  }> = {
    'waf-posture': {
      metricCards: [
        { label: 'WAF assets', value: data.wafAssets.length, sub: 'Declared protected services', icon: ShieldCheck, tone: 'info' },
        { label: 'Protected', value: `${Math.round(protectedPercent)}%`, sub: `${getNumber(data.wafCoverage ?? {}, ['protected'])}/${getNumber(data.wafCoverage ?? {}, ['total_assets'])} assets`, icon: CheckCircle2, tone: protectedPercent >= 80 ? 'success' : 'warn' },
        { label: 'Drift events', value: data.wafDriftEvents.length, sub: 'Posture changes', icon: TriangleAlert, tone: data.wafDriftEvents.length > 0 ? 'warn' : 'success' }
      ],
      columns: [
        { key: 'asset', label: 'Asset', render: (item) => getString(item, ['canonical_url', 'display_ref', 'id']) },
        { key: 'status', label: 'Status', render: (item) => <Badge tone={getString(item, ['status'], 'unknown') === 'protected' ? 'success' : 'warn'}>{getString(item, ['status'], 'unknown')}</Badge> },
        { key: 'vendor', label: 'Vendor', render: (item) => getString(item, ['detected_vendor', 'expected_vendor_hint', 'provider']) },
        { key: 'criticality', label: 'Criticality', render: (item) => getString(item, ['business_criticality', 'criticality']) },
        { key: 'updated', label: 'Updated', render: (item) => formatDate(item.updated_at ?? item.created_at) },
        {
          key: 'detail',
          label: 'Detail',
          render: (item) => {
            const id = getString(item, ['id'], '');
            return id ? <AnchorButton size="sm" variant="secondary" href={buildDetailHref('waf-asset-detail', id)}>Open</AnchorButton> : null;
          }
        }
      ],
      items: data.wafAssets,
      emptyTitle: 'No WAF assets recorded.',
      emptyBody: 'Create a declared WAF asset or import from an approved connector snapshot.'
    },
    'cve-pipeline': {
      metricCards: [
        { label: 'CVE items', value: data.cvePipeline.length, sub: 'Pipeline records', icon: TriangleAlert, tone: data.cvePipeline.length > 0 ? 'warn' : 'success' },
        { label: 'Known exploited', value: data.cvePipeline.filter((item) => item.known_exploited === true).length, sub: 'KEV flagged', icon: Siren, tone: 'danger' },
        { label: 'Validations', value: data.wafValidations.length, sub: 'Safe validation bindings', icon: ListChecks, tone: 'info' }
      ],
      columns: [
        { key: 'cve', label: 'CVE', render: (item) => getString(item, ['cve_id', 'id']) },
        { key: 'severity', label: 'Severity', render: (item) => <Badge tone={['critical', 'high'].includes(getString(item, ['severity']).toLowerCase()) ? 'danger' : 'warn'}>{getString(item, ['severity'])}</Badge> },
        { key: 'stage', label: 'Stage', render: (item) => getString(item, ['stage', 'status']) },
        {
          key: 'detail',
          label: 'Detail',
          render: (item) => {
            const id = getString(item, ['id'], '');
            return id ? <AnchorButton size="sm" variant="secondary" href={buildDetailHref('cve-detail', id)}>Open</AnchorButton> : null;
          }
        },
        {
          key: 'actions',
          label: 'Actions',
          render: (item) => {
            const id = getString(item, ['id'], '');
            return (
              <div className="row-actions">
                <Button size="sm" variant="secondary" disabled={busy !== ''} onClick={() => void handleAction(`triage-${id}`, () => requestJson(config, session, `/v1/waf/cve-pipeline/${id}/triage`, { method: 'POST', body: {} }), 'CVE item triaged.')}>Triage</Button>
                <Button size="sm" variant="ghost" disabled={busy !== ''} onClick={() => void handleAction(`validate-${id}`, () => requestJson(config, session, `/v1/waf/cve-pipeline/${id}/validate`, { method: 'POST' }), 'Safe validation delegated.')}>Validate</Button>
              </div>
            );
          }
        }
      ],
      items: data.cvePipeline,
      emptyTitle: 'No CVE pipeline records.',
      emptyBody: 'Ingest a feed or create a CVE item manually.'
    },
    'supply-chain': {
      metricCards: [
        { label: 'Risks', value: data.supplyChainRisks.length, sub: 'Supply-chain records', icon: Network, tone: data.supplyChainRisks.length > 0 ? 'warn' : 'success' },
        { label: 'High severity', value: data.supplyChainRisks.filter((item) => ['critical', 'high'].includes(getString(item, ['severity']).toLowerCase())).length, sub: 'Needs review', icon: TriangleAlert, tone: 'danger' },
        { label: 'Authorized phases', value: data.supplyChainRisks.filter((item) => Array.isArray(item.phase_authorizations) && item.phase_authorizations.length > 0).length, sub: 'Customer-approved', icon: FileCheck2, tone: 'info' }
      ],
      columns: [
        { key: 'host', label: 'Host', render: (item) => getString(item, ['hostname', 'id']) },
        { key: 'type', label: 'Exposure', render: (item) => getString(item, ['exposure_type']) },
        { key: 'severity', label: 'Severity', render: (item) => <Badge tone={['critical', 'high'].includes(getString(item, ['severity']).toLowerCase()) ? 'danger' : 'warn'}>{getString(item, ['severity'])}</Badge> },
        { key: 'state', label: 'State', render: (item) => getString(item, ['state']) },
        {
          key: 'detail',
          label: 'Detail',
          render: (item) => {
            const id = getString(item, ['id'], '');
            return id ? <AnchorButton size="sm" variant="secondary" href={buildDetailHref('supply-chain-detail', id)}>Open</AnchorButton> : null;
          }
        }
      ],
      items: data.supplyChainRisks,
      emptyTitle: 'No supply-chain risks recorded.',
      emptyBody: 'Create a metadata-only supply-chain risk record.'
    },
    remediation: {
      metricCards: [
        { label: 'Action items', value: data.wafActionItems.length, sub: 'Remediation tasks', icon: ClipboardList, tone: data.wafActionItems.length > 0 ? 'warn' : 'success' },
        { label: 'Open', value: data.wafActionItems.filter((item) => !CLOSED_ACTION_ITEM_STATUSES.has(getString(item, ['status']).toLowerCase())).length, sub: 'Not closed', icon: Clock3, tone: 'warn' },
        { label: 'Exceptions', value: data.wafExceptions.length, sub: 'Approved exceptions', icon: FileCheck2, tone: 'info' }
      ],
      columns: [
        { key: 'title', label: 'Action item', render: (item) => getString(item, ['title', 'id']) },
        { key: 'severity', label: 'Severity', render: (item) => <Badge tone={['critical', 'high'].includes(getString(item, ['severity']).toLowerCase()) ? 'danger' : 'warn'}>{getString(item, ['severity'])}</Badge> },
        {
          key: 'status',
          label: 'Status',
          render: (item) => {
            const id = getString(item, ['action_item_id', 'id'], '');
            const status = getString(item, ['status'], 'open');
            return (
              <select
                className="inline-select"
                value={status}
                disabled={busy !== ''}
                onChange={(event) => void handleAction(`patch-action-${id}`, () => requestJson(config, session, `/v1/waf/action-items/${id}`, { method: 'PATCH', body: { status: event.target.value } }), 'Action item status updated.')}
              >
                {ACTION_ITEM_STATUSES.map((value) => <option key={value} value={value}>{value.replace(/_/g, ' ')}</option>)}
              </select>
            );
          }
        },
        {
          key: 'actions',
          label: 'Actions',
          render: (item) => {
            const id = getString(item, ['action_item_id', 'id'], '');
            return (
              <div className="row-actions">
                <Button size="sm" variant="secondary" disabled={busy !== ''} onClick={() => setSelectedActionItemId(id)}>Deliver</Button>
              </div>
            );
          }
        }
      ],
      items: data.wafActionItems,
      emptyTitle: 'No remediation action items.',
      emptyBody: 'Create action items from WAF findings.'
    },
    discovery: {
      metricCards: [
        { label: 'Entities', value: data.discoveryEntities.length, sub: 'Approved entities', icon: Network, tone: 'info' },
        { label: 'Candidates', value: data.discoveryCandidates.length, sub: 'Awaiting decision', icon: ScanSearch, tone: data.discoveryCandidates.length > 0 ? 'warn' : 'success' },
        { label: 'Inbox', value: data.discoveryInbox.length, sub: 'Pending review', icon: ClipboardList, tone: data.discoveryInbox.length > 0 ? 'warn' : 'success' }
      ],
      columns: [
        { key: 'candidate', label: 'Candidate', render: (item) => getString(item, ['value', 'hostname', 'entity_id', 'id']) },
        { key: 'type', label: 'Type', render: (item) => getString(item, ['entity_type', 'candidate_type', 'type']) },
        { key: 'state', label: 'State', render: (item) => <Badge tone={getString(item, ['state']) === 'approved' ? 'success' : 'warn'}>{getString(item, ['state'])}</Badge> },
        {
          key: 'actions',
          label: 'Actions',
          render: (item) => {
            const id = getString(item, ['id', 'entity_id'], '');
            const state = getString(item, ['state'], '');
            return (
              <div className="row-actions">
                {id ? <AnchorButton size="sm" variant="secondary" href={buildDetailHref('discovery-entity', id)}>Detail</AnchorButton> : null}
                {state === 'approved' || state === 'approved_target' || state === 'rejected' ? null : (
                  <>
                    <select
                      className="inline-select"
                      value={approveTargetGroupByCandidate[id] ?? defaultTargetGroupId}
                      disabled={busy !== '' || data.targetGroups.length === 0}
                      onChange={(event) => setApproveTargetGroupByCandidate((current) => ({ ...current, [id]: event.target.value }))}
                      aria-label={`Approve ${getString(item, ['value', 'hostname'], id)} into target group`}
                    >
                      {data.targetGroups.length === 0 ? <option value="">No target groups declared</option> : null}
                      {data.targetGroups.map((group) => (
                        <option key={getString(group, ['id'])} value={getString(group, ['id'])}>{getString(group, ['name', 'id'])}</option>
                      ))}
                    </select>
                    <Button
                      size="sm"
                      variant="secondary"
                      disabled={busy !== '' || data.targetGroups.length === 0 || !resolveTargetGroupId(id, approveTargetGroupByCandidate)}
                      onClick={() => {
                        const targetGroupId = resolveTargetGroupId(id, approveTargetGroupByCandidate);
                        if (!targetGroupId) {
                          setError('Select a target group before approving this candidate.');
                          return;
                        }
                        void handleAction(`approve-${id}`, () => requestJson(config, session, `/v1/discovery/candidates/${id}/approve`, { method: 'POST', body: { target_group_id: targetGroupId } }), 'Candidate approved.');
                      }}
                    >
                      Approve
                    </Button>
                    <Button size="sm" variant="ghost" disabled={busy !== ''} onClick={() => void handleAction(`reject-${id}`, () => requestJson(config, session, `/v1/discovery/candidates/${id}/reject`, { method: 'POST', body: { reason: 'not_in_scope' } }), 'Candidate rejected.')}>Reject</Button>
                  </>
                )}
                {state === 'approved_target' && !getString(item, ['approved_target_id'], '') ? (
                  <>
                    <select
                      className="inline-select"
                      value={importTargetGroupByCandidate[id] ?? defaultTargetGroupId}
                      disabled={busy !== '' || data.targetGroups.length === 0}
                      onChange={(event) => setImportTargetGroupByCandidate((current) => ({ ...current, [id]: event.target.value }))}
                      aria-label={`Import ${getString(item, ['value', 'hostname'], id)} into target group`}
                    >
                      {data.targetGroups.map((group) => (
                        <option key={getString(group, ['id'])} value={getString(group, ['id'])}>{getString(group, ['name', 'id'])}</option>
                      ))}
                    </select>
                    <Button
                      size="sm"
                      variant="secondary"
                      disabled={busy !== '' || data.targetGroups.length === 0}
                      onClick={() => void handleAction(`import-${id}`, () => requestJson(config, session, `/v1/discovery/candidates/${id}/import`, {
                        method: 'POST',
                        body: {
                          target_group_id: importTargetGroupByCandidate[id] ?? defaultTargetGroupId,
                          create_waf_asset: true
                        }
                      }), 'Candidate imported into declared target group.')}
                    >
                      Import to target group
                    </Button>
                  </>
                ) : null}
              </div>
            );
          }
        }
      ],
      items: data.discoveryCandidates.length > 0 ? data.discoveryCandidates : data.discoveryEntities,
      emptyTitle: 'No discovery records.',
      emptyBody: 'Declare an entity or ingest passive discovery candidates.'
    }
  };

  const tableConfig = routeConfig[route] ?? routeConfig['waf-posture'];
  const targetGroupNameById = Object.fromEntries(
    data.targetGroups.map((group) => [getString(group, ['id'], ''), getString(group, ['name', 'id'], '')])
  );
  const wafAssetColumns: TableColumn<DataItem>[] = [
    { key: 'asset', label: 'Asset', render: (item) => getString(item, ['canonical_url', 'display_ref', 'hostname', 'id']) },
    { key: 'status', label: 'Status', render: (item) => <Badge tone={getString(item, ['status', 'posture_status'], 'unknown') === 'protected' ? 'success' : 'warn'}>{getString(item, ['status', 'posture_status'], 'unknown')}</Badge> },
    { key: 'vendor', label: 'Vendor', render: (item) => getString(item, ['detected_vendor', 'expected_vendor_hint', 'provider']) },
    {
      key: 'pass-rate',
      label: 'Pass rate',
      render: (item) => {
        const effectiveness = getNestedItem(item, ['effectiveness']);
        const passRate = typeof effectiveness?.scenario_pass_rate === 'number'
          ? effectiveness.scenario_pass_rate
          : computeWafAssetPassRate(getString(item, ['id'], ''), data.wafValidations);
        return formatWafPassRateDisplay(passRate);
      }
    },
    {
      key: 'rule-health',
      label: 'Rule health',
      render: (item) => formatWafRuleHealthDisplay(getNestedItem(item, ['effectiveness']))
    },
    { key: 'target-group', label: 'Target group', render: (item) => targetGroupNameById[getString(item, ['target_group_id'], '')] || getString(item, ['target_group_id']) },
    { key: 'owner', label: 'Owner', render: (item) => getString(item, ['owner_hint']) },
    {
      key: 'detail',
      label: 'Detail',
      render: (item) => {
        const id = getString(item, ['id'], '');
        return id ? <AnchorButton size="sm" variant="secondary" href={buildDetailHref('waf-asset-detail', id)}>Open</AnchorButton> : null;
      }
    }
  ];
  const roadmapTiers = (data.wafRiskRoadmap?.tiers as Record<string, DataItem[]> | undefined) ?? {};
  const roadmapMethod = getString(data.wafRiskRoadmap ?? {}, ['method'], '');
  const roadmapGeneratedAt = formatDate(data.wafRiskRoadmap?.generated_at);
  const roadmapItemCount = roadmapTotalItems(roadmapTiers);

  function renderWafRoadmapPanel() {
    if (!roadmapItemCount) {
      const emptyCopy = roadmapMethod
        ? 'No roadmap items yet. Declare assets and finalize safe validations so risk scoring can rank deployment priorities.'
        : 'Risk scoring has not produced roadmap tiers yet. Finalize validations on declared assets to seed risk scores.';
      return (
        <Card>
          <CardHeader>
            <CardTitle>Deployment roadmap</CardTitle>
            <CardDescription>Tiered WAF deployment priorities from `GET /v1/waf/coverage/risk-roadmap`.</CardDescription>
          </CardHeader>
          <CardContent>
            <EmptyState icon={ShieldCheck} title="Roadmap awaiting risk scores" body={emptyCopy} />
          </CardContent>
        </Card>
      );
    }

    return (
      <Card>
        <CardHeader>
          <CardTitle>Deployment roadmap</CardTitle>
          <CardDescription>
            Tiered priorities from `/v1/waf/coverage/risk-roadmap` · generated {roadmapGeneratedAt} · method {roadmapMethod || '—'}
          </CardDescription>
        </CardHeader>
        <CardContent className="tab-panel-layout">
          {roadmapTierIds().map((tierId) => {
            const items = roadmapTiers[tierId] ?? [];
            const meta = roadmapTierMeta(tierId);
            const columns: TableColumn<DataItem>[] = [
              { key: 'asset', label: 'Asset', render: (item) => getString(item, ['hostname', 'waf_asset_id', 'canonical_url']) },
              { key: 'owner', label: 'Owner', render: (item) => getString(item, ['owner_hint']) },
              { key: 'risk', label: 'Risk', render: (item) => getString(item, ['risk_score']) },
              { key: 'status', label: 'Status', render: (item) => <Badge tone={getString(item, ['posture_status'], 'unknown') === 'protected' ? 'success' : 'warn'}>{getString(item, ['posture_status'], 'unknown')}</Badge> },
              {
                key: 'gap',
                label: 'Primary gap',
                render: (item) => {
                  const codes = Array.isArray(item.primary_reason_codes) ? item.primary_reason_codes as string[] : [];
                  return codes.length ? codes.join(', ') : '—';
                }
              },
              { key: 'action', label: 'Recommended action', render: (item) => getString(item, ['recommended_action'], 'Review WAF posture gap.') },
              { key: 'vendor', label: 'Vendor', render: (item) => getString(item, ['detected_vendor'], 'none') }
            ];
            return (
              <div key={tierId}>
                <h4>{meta.label} <span className="muted">({meta.window})</span></h4>
                <DataTable
                  columns={columns}
                  items={items}
                  empty={<EmptyState icon={ShieldCheck} title={`No assets in ${meta.label}`} body="This tier is empty for the current risk snapshot." />}
                />
              </div>
            );
          })}
        </CardContent>
      </Card>
    );
  }

  function rememberRetest(driftEventId: string, retest: DataItem | null | undefined) {
    if (!driftEventId || !retest || typeof retest !== 'object') return;
    setSessionRetestsByDrift((current) => ({ ...current, [driftEventId]: retest }));
  }

  function resolveDriftRetest(driftEventId: string) {
    return sessionRetestsByDrift[driftEventId] ?? retestForDriftEvent(data.wafRetests, driftEventId);
  }

  function defaultExceptionExpiryIso(daysAhead = 90) {
    const expires = new Date();
    expires.setUTCDate(expires.getUTCDate() + daysAhead);
    return expires.toISOString();
  }

  function renderWafOperatorPanels() {
    const driftColumns: TableColumn<DataItem>[] = [
      { key: 'type', label: 'Drift type', render: (item) => getString(item, ['drift_type', 'reason_code', 'type']) },
      { key: 'asset', label: 'Asset', render: (item) => getString(item, ['waf_asset_id', 'canonical_url', 'hostname']) },
      { key: 'severity', label: 'Severity', render: (item) => <Badge tone={['critical', 'high'].includes(getString(item, ['severity']).toLowerCase()) ? 'danger' : 'warn'}>{getString(item, ['severity'])}</Badge> },
      { key: 'seen', label: 'First seen', render: (item) => formatDate(item.first_seen_at ?? item.created_at) },
      {
        key: 'status',
        label: 'Status',
        render: (item) => {
          const id = getString(item, ['id'], '');
          const status = getString(item, ['status'], 'open');
          return (
            <select
              className="inline-select"
              value={status}
              disabled={busy !== ''}
              onChange={(event) => void handleAction(`patch-drift-${id}`, () => requestJson(config, session, `/v1/waf/drift-events/${id}`, {
                method: 'PATCH',
                body: { status: event.target.value }
              }), 'Drift status updated.')}
            >
              {DRIFT_EVENT_STATUSES.map((value) => <option key={value} value={value}>{value.replace(/_/g, ' ')}</option>)}
            </select>
          );
        }
      },
      {
        key: 'retest',
        label: 'Retest',
        render: (item) => {
          const driftId = getString(item, ['id'], '');
          const retest = resolveDriftRetest(driftId);
          const retestId = getString(retest, ['id'], '');
          const retestStatus = getString(retest, ['status'], 'none');
          return (
            <div className="stack-tight">
              <span className="muted small">{retestId ? `${retestId} · ${retestStatus}` : 'No retest yet'}</span>
              <div className="row-actions">
                <Button
                  size="sm"
                  variant="secondary"
                  disabled={busy !== ''}
                  onClick={() => void handleAction(`drift-retest-${driftId}`, async () => {
                    const payload = await requestJson(config, session, `/v1/waf/drift-events/${driftId}/retest`, { method: 'POST', body: {} }) as { retest_request?: DataItem };
                    rememberRetest(driftId, payload?.retest_request);
                    return payload;
                  }, 'Retest requested.')}
                >
                  Request
                </Button>
                {retestId ? (
                  <>
                    <Button
                      size="sm"
                      variant="ghost"
                      disabled={busy !== ''}
                      onClick={() => void handleAction(`retest-exec-${retestId}`, async () => {
                        const payload = await requestJson(config, session, `/v1/waf/retests/${retestId}/execute`, { method: 'POST', body: {} }) as { retest_request?: DataItem };
                        rememberRetest(driftId, payload?.retest_request ?? retest);
                        return payload;
                      }, 'Retest execution delegated.')}
                    >
                      Execute
                    </Button>
                    <Button
                      size="sm"
                      variant="ghost"
                      disabled={busy !== ''}
                      onClick={() => void handleAction(`retest-complete-${retestId}`, async () => {
                        const payload = await requestJson(config, session, `/v1/waf/retests/${retestId}/complete`, { method: 'POST' }) as { retest_request?: DataItem };
                        rememberRetest(driftId, payload?.retest_request ?? retest);
                        return payload;
                      }, 'Retest completed from verdict evidence.')}
                    >
                      Complete
                    </Button>
                  </>
                ) : null}
              </div>
            </div>
          );
        }
      }
    ];

    const planColumns: TableColumn<DataItem>[] = [
      { key: 'id', label: 'Plan', render: (item) => getString(item, ['id']) },
      { key: 'target', label: 'Target group', render: (item) => getString(item, ['target_group_id']) },
      { key: 'state', label: 'State', render: (item) => <Badge tone={getString(item, ['state']) === 'completed' ? 'success' : 'warn'}>{getString(item, ['state'])}</Badge> },
      {
        key: 'scenarios',
        label: 'Scenarios',
        render: (item) => (Array.isArray(item.scenarios) ? (item.scenarios as string[]).join(', ') : '—')
      },
      {
        key: 'actions',
        label: 'Actions',
        render: (item) => {
          const id = getString(item, ['id'], '');
          const state = getString(item, ['state'], '');
          return (
            <div className="row-actions">
              {!['completed', 'cancelled'].includes(state) ? (
                <Button size="sm" variant="secondary" disabled={busy !== ''} onClick={() => void handleAction(`plan-exec-${id}`, () => requestJson(config, session, `/v1/waf/validation-plans/${id}/execute`, { method: 'POST' }), 'Validation plan execute tick completed.')}>Execute</Button>
              ) : null}
              {!['completed', 'cancelled'].includes(state) ? (
                <Button size="sm" variant="ghost" disabled={busy !== ''} onClick={() => void handleAction(`plan-cancel-${id}`, () => requestJson(config, session, `/v1/waf/validation-plans/${id}/cancel`, { method: 'POST' }), 'Validation plan cancelled.')}>Cancel</Button>
              ) : null}
            </div>
          );
        }
      }
    ];

    const exceptionColumns: TableColumn<DataItem>[] = [
      { key: 'asset', label: 'Asset', render: (item) => getString(item, ['waf_asset_id', 'asset_id']) },
      { key: 'owner', label: 'Owner', render: (item) => getString(item, ['owner']) },
      { key: 'reason', label: 'Reason', render: (item) => getString(item, ['reason']) },
      { key: 'expires', label: 'Expires', render: (item) => formatDate(item.expires_at) }
    ];

    return (
      <>
        <Card>
          <CardHeader>
            <CardTitle>Drift scan</CardTitle>
            <CardDescription>Metadata-only posture drift comparison via `POST /v1/waf/drift-scans/run`.</CardDescription>
          </CardHeader>
          <CardContent className="product-form">
            <div className="kv-list">
              <div><span>Latest scan</span><strong>{driftScanLatest ? formatDate(driftScanLatest.completed_at ?? driftScanLatest.created_at) : 'None yet'}</strong></div>
              <div><span>Events opened</span><strong>{getString(driftScanLatest ?? {}, ['events_opened'], String(getNumber(driftScanLatest ?? {}, ['drift_events_created'])))}</strong></div>
            </div>
            <div className="form-actions">
              <Button
                disabled={busy !== ''}
                onClick={() => void handleAction('drift-scan-run', async () => {
                  const payload = await requestJson(config, session, '/v1/waf/drift-scans/run', { method: 'POST' }) as { scan_result?: DataItem };
                  if (payload?.scan_result) setDriftScanLatest(payload.scan_result);
                  return payload;
                }, 'Drift scan completed.')}
              >
                Run drift scan
              </Button>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>Drift events</CardTitle>
            <CardDescription>Workflow status and safe retest controls from `/v1/waf/drift-events` and `/v1/waf/retests`.</CardDescription>
          </CardHeader>
          <CardContent>
            <DataTable
              columns={driftColumns}
              items={data.wafDriftEvents}
              empty={<EmptyState icon={TriangleAlert} title="No drift events." body="Drift events appear after posture weakens or drift scans detect changes." />}
            />
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>Validation plans (operator)</CardTitle>
            <CardDescription>Safe orchestrator plans from `/v1/waf/validation-plans`; production scheduling still uses external runner.</CardDescription>
          </CardHeader>
          <CardContent className="stack">
            <form className="product-form" onSubmit={(event: FormEvent<HTMLFormElement>) => {
              event.preventDefault();
              const formElement = event.currentTarget;
              const form = new FormData(formElement);
              const targetGroupId = String(form.get('target_group_id') ?? defaultTargetGroupId).trim();
              if (!targetGroupId) {
                setError('Select a target group before creating a validation plan.');
                return;
              }
              const scenarios = VALIDATION_PLAN_SCENARIOS.filter((scenario) => form.get(`scenario_${scenario}`) === 'on');
              void handleAction('create-validation-plan', () => requestJson(config, session, '/v1/waf/validation-plans', {
                method: 'POST',
                body: {
                  target_group_id: targetGroupId,
                  mode: String(form.get('mode') ?? 'manual').trim(),
                  scenarios: scenarios.length > 0 ? scenarios : ['marker', 'fingerprint'],
                  max_concurrent: Number(form.get('max_concurrent') ?? 2)
                }
              }), 'Validation plan created.');
              formElement.reset();
            }}>
              <label><span>Target group</span>
                <select name="target_group_id" defaultValue={defaultTargetGroupId} required>
                  {data.targetGroups.map((group) => <option key={getString(group, ['id'])} value={getString(group, ['id'])}>{getString(group, ['name', 'id'])}</option>)}
                </select>
              </label>
              <label><span>Mode</span>
                <select name="mode" defaultValue="manual"><option value="manual">manual</option><option value="on_demand">on_demand</option></select>
              </label>
              <label><span>Max concurrent</span><input name="max_concurrent" type="number" min="1" max="10" defaultValue="2" /></label>
              <div className="check-row full">
                {VALIDATION_PLAN_SCENARIOS.map((scenario) => (
                  <label key={scenario} className="check-row"><input name={`scenario_${scenario}`} type="checkbox" defaultChecked={scenario === 'marker' || scenario === 'fingerprint'} /><span>{scenario}</span></label>
                ))}
              </div>
              <div className="form-actions full"><Button type="submit" disabled={busy !== '' || data.targetGroups.length === 0}>Create plan</Button></div>
            </form>
            <DataTable
              columns={planColumns}
              items={data.wafValidationPlans}
              empty={<EmptyState icon={ListChecks} title="No validation plans." body="Create a safe validation plan for a declared target group." />}
            />
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>Approved exceptions</CardTitle>
            <CardDescription>Tenant-scoped metadata-only exceptions from `GET /v1/waf/exceptions` and `POST /v1/waf/assets/:id/exception`.</CardDescription>
          </CardHeader>
          <CardContent className="stack">
            <form className="product-form" onSubmit={(event: FormEvent<HTMLFormElement>) => {
              event.preventDefault();
              const formElement = event.currentTarget;
              const form = new FormData(formElement);
              const assetId = String(form.get('waf_asset_id') ?? exceptionAssetId).trim();
              if (!assetId) {
                setError('Select a WAF asset before creating an exception.');
                return;
              }
              void handleAction('create-waf-exception', () => requestJson(config, session, `/v1/waf/assets/${encodeURIComponent(assetId)}/exception`, {
                method: 'POST',
                body: {
                  owner: String(form.get('owner') ?? 'edge-team').trim(),
                  reason: String(form.get('reason') ?? 'approved_scope_exception').trim(),
                  expires_at: defaultExceptionExpiryIso()
                }
              }), 'WAF exception recorded.');
              formElement.reset();
            }}>
              <label><span>WAF asset</span>
                <select name="waf_asset_id" value={exceptionAssetId} onChange={(event) => setExceptionAssetId(event.target.value)} required>
                  {data.wafAssets.length === 0 ? <option value="">No assets declared</option> : null}
                  {data.wafAssets.map((asset) => {
                    const id = getString(asset, ['id'], '');
                    return <option key={id} value={id}>{getString(asset, ['canonical_url', 'display_ref', 'id'])}</option>;
                  })}
                </select>
              </label>
              <label><span>Owner</span><input name="owner" defaultValue="edge-team" required /></label>
              <label className="full"><span>Reason</span><input name="reason" defaultValue="approved_scope_exception" required /></label>
              <div className="form-actions full"><Button type="submit" disabled={busy !== '' || data.wafAssets.length === 0}>Create exception</Button></div>
            </form>
            <DataTable
              columns={exceptionColumns}
              items={data.wafExceptions}
              empty={<EmptyState icon={FileCheck2} title="No active exceptions." body="Approved exceptions appear here after asset-scoped exception creation." />}
            />
          </CardContent>
        </Card>
      </>
    );
  }

  function renderCreateForm() {
    if (route === 'waf-posture') {
      return (
        <form className="product-form" onSubmit={(event: FormEvent<HTMLFormElement>) => {
          event.preventDefault();
          const formElement = event.currentTarget;
          const form = new FormData(formElement);
          const targetGroupId = String(form.get('target_group_id') ?? wafAssetTargetGroupId).trim();
          const targetId = String(form.get('target_id') ?? '').trim();
          if (!targetGroupId) {
            setError('Select a declared target group before creating a WAF asset.');
            return;
          }
          if (!targetId) {
            setError('Select a target from the chosen group before creating a WAF asset.');
            return;
          }
          void handleAction('create-waf-asset', () => requestJson(config, session, '/v1/waf/assets', {
            method: 'POST',
            body: {
              target_group_id: targetGroupId,
              target_id: targetId,
              canonical_url: String(form.get('canonical_url') ?? '').trim(),
              owner_hint: String(form.get('owner_hint') ?? 'edge-team').trim()
            }
          }), 'WAF asset created.');
          formElement.reset();
        }}>
          <label><span>Target group</span>
            <select
              name="target_group_id"
              value={wafAssetTargetGroupId}
              disabled={data.targetGroups.length === 0}
              onChange={(event) => setWafAssetTargetGroupId(event.target.value)}
            >
              {data.targetGroups.length === 0 ? <option value="">No target groups declared</option> : null}
              {data.targetGroups.map((g) => <option key={getString(g, ['id'])} value={getString(g, ['id'])}>{getString(g, ['name', 'id'])}</option>)}
            </select>
          </label>
          <label><span>Target</span>
            <select name="target_id" defaultValue="" disabled={wafAssetTargetsLoading || wafAssetTargets.length === 0} required>
              <option value="">{wafAssetTargetsLoading ? 'Loading targets…' : wafAssetTargets.length === 0 ? 'Add a target to the selected group' : 'Select target'}</option>
              {wafAssetTargets.map((target) => {
                const targetId = getString(target, ['id'], '');
                return <option key={targetId} value={targetId}>{getString(target, ['value', 'id'])} ({getString(target, ['kind'], 'target')})</option>;
              })}
            </select>
          </label>
          <label><span>Canonical URL</span><input name="canonical_url" placeholder="https://app.example.com" required /></label>
          <label><span>Owner hint</span><input name="owner_hint" defaultValue="edge-team" /></label>
          <div className="form-actions full"><Button type="submit" disabled={busy !== '' || data.targetGroups.length === 0 || wafAssetTargets.length === 0}>Create WAF asset</Button></div>
        </form>
      );
    }
    if (route === 'cve-pipeline') {
      return (
        <form className="product-form" onSubmit={(event: FormEvent<HTMLFormElement>) => {
          event.preventDefault();
          const formElement = event.currentTarget;
          const form = new FormData(formElement);
          void handleAction('create-cve', () => requestJson(config, session, '/v1/waf/cve-pipeline', {
            method: 'POST',
            body: {
              cve_id: String(form.get('cve_id') ?? '').trim(),
              severity: String(form.get('severity') ?? 'high').trim(),
              affected_products: String(form.get('affected_products') ?? 'declared-service').trim().split(',').map((value) => value.trim()).filter(Boolean),
              known_exploited: form.get('known_exploited') === 'on'
            }
          }), 'CVE pipeline item created.');
          formElement.reset();
        }}>
          <label><span>CVE ID</span><input name="cve_id" placeholder="CVE-2026-0001" required /></label>
          <label><span>Affected products</span><input name="affected_products" defaultValue="declared-service" required /></label>
          <label><span>Severity</span>
            <select name="severity" defaultValue="high"><option value="critical">critical</option><option value="high">high</option><option value="medium">medium</option></select>
          </label>
          <label className="check-row full"><input name="known_exploited" type="checkbox" /><span>Known exploited (KEV)</span></label>
          <div className="form-actions full"><Button type="submit" disabled={busy !== ''}>Create CVE item</Button></div>
        </form>
      );
    }
    if (route === 'supply-chain') {
      return (
        <form className="product-form" onSubmit={(event: FormEvent<HTMLFormElement>) => {
          event.preventDefault();
          const formElement = event.currentTarget;
          const form = new FormData(formElement);
          void handleAction('create-risk', () => requestJson(config, session, '/v1/waf/supply-chain/risks', {
            method: 'POST',
            body: {
              exposure_type: String(form.get('exposure_type') ?? 'dangling_cname').trim(),
              hostname: String(form.get('hostname') ?? '').trim(),
              severity: String(form.get('severity') ?? 'high').trim(),
              confidence: Number(form.get('confidence') ?? 0.8),
              state: 'suspected',
              evidence_summary: { data_source: 'customer_declared' },
              remediation_steps: ['Review DNS chain and remove dangling reference.']
            }
          }), 'Supply-chain risk created.');
          formElement.reset();
        }}>
          <label><span>Hostname</span><input name="hostname" placeholder="orphan.example.com" required /></label>
          <label><span>Exposure type</span><input name="exposure_type" defaultValue="dangling_cname" /></label>
          <label><span>Severity</span><select name="severity" defaultValue="high"><option value="critical">critical</option><option value="high">high</option></select></label>
          <label><span>Confidence</span><input name="confidence" type="number" min="0" max="1" step="0.1" defaultValue="0.8" /></label>
          <div className="form-actions full"><Button type="submit" disabled={busy !== ''}>Create risk</Button></div>
        </form>
      );
    }
    if (route === 'remediation') {
      return (
        <form className="product-form" onSubmit={(event: FormEvent<HTMLFormElement>) => {
          event.preventDefault();
          const formElement = event.currentTarget;
          const form = new FormData(formElement);
          const findingId = String(form.get('finding_id') ?? '').trim();
          if (!findingId) {
            setError('Select a finding before creating an action item.');
            return;
          }
          void handleAction('create-action-item', () => requestJson(config, session, '/v1/waf/action-items', {
            method: 'POST',
            body: { finding_id: findingId }
          }), 'Remediation action item created.');
          formElement.reset();
        }}>
          <label><span>Finding</span>
            <select name="finding_id" defaultValue={firstFindingId} required>
              {data.findings.length === 0 ? <option value="">No findings available</option> : null}
              {data.findings.map((finding) => {
                const id = getString(finding, ['id'], '');
                return <option key={id} value={id}>{getString(finding, ['title', 'id'])} ({getString(finding, ['severity'])})</option>;
              })}
            </select>
          </label>
          <div className="form-actions full"><Button type="submit" disabled={busy !== '' || data.findings.length === 0}>Create action item</Button></div>
        </form>
      );
    }
    if (route === 'discovery') {
      return (
        <form className="product-form" onSubmit={(event: FormEvent<HTMLFormElement>) => {
          event.preventDefault();
          const formElement = event.currentTarget;
          const form = new FormData(formElement);
          const rootDomain = String(form.get('root_domain') ?? '').trim().toLowerCase();
          const displayName = String(form.get('display_name') ?? '').trim();
          const entityId = String(form.get('entity_id') ?? '').trim() || `ent_${rootDomain.replace(/[^a-z0-9]+/g, '_').replace(/^_|_$/g, '') || 'declared'}`;
          if (!rootDomain) {
            setError('Enter a root domain before declaring an entity.');
            return;
          }
          void handleAction('create-entity', () => requestJson(config, session, '/v1/discovery/entities', {
            method: 'POST',
            body: {
              entity_id: entityId,
              entity_type: String(form.get('entity_type') ?? 'parent_organization').trim(),
              name: displayName || rootDomain,
              display_name: displayName || rootDomain,
              root_domains: [rootDomain],
              country: String(form.get('country') ?? 'US').trim(),
              confidence: Number(form.get('confidence') ?? 0.85),
              source: String(form.get('source') ?? 'customer_import').trim()
            }
          }), 'Discovery entity declared.');
          formElement.reset();
        }}>
          <label><span>Entity ID</span><input name="entity_id" placeholder="ent_acme (optional)" /></label>
          <label><span>Type</span>
            <select name="entity_type" defaultValue="parent_organization">
              <option value="parent_organization">parent organization</option>
              <option value="subsidiary">subsidiary</option>
              <option value="brand">brand</option>
              <option value="region">region</option>
            </select>
          </label>
          <label><span>Display name</span><input name="display_name" placeholder="Acme Corp" /></label>
          <label><span>Root domain</span><input name="root_domain" placeholder="example.com" required /></label>
          <label><span>Country</span><input name="country" defaultValue="US" /></label>
          <label><span>Confidence</span><input name="confidence" type="number" min="0" max="1" step="0.05" defaultValue="0.85" /></label>
          <label><span>Source</span><input name="source" defaultValue="customer_import" /></label>
          <div className="form-actions full"><Button type="submit" disabled={busy !== ''}>Declare entity</Button></div>
        </form>
      );
    }
    return null;
  }

  return (
    <div className="content">
      <PageHeader route={route} />
      {!enabled ? (
        <Card>
          <CardHeader>
            <CardTitle>{requiresWaf ? 'WAF posture disabled' : 'External discovery disabled'}</CardTitle>
            <CardDescription>Optional add-ons fail closed when their feature flag is off.</CardDescription>
          </CardHeader>
          <CardContent>
            <EmptyState icon={ShieldCheck} title={requiresWaf ? 'Enable ASTRANULL_WAF_POSTURE_ENABLED=1' : 'Enable ASTRANULL_EXTERNAL_DISCOVERY_ENABLED=1'} body="No posture data is invented while the backend route family is disabled." />
          </CardContent>
        </Card>
      ) : (
        <>
          {(message || error) && <div className={error ? 'form-banner error' : 'form-banner'}>{error || message}</div>}
          <div className="metric-grid three">
            {tableConfig.metricCards.map((metric) => <MetricCard key={metric.label} {...metric} />)}
          </div>
          {route === 'waf-posture' ? (
            <Tabs
              value={wafPostureTab}
              options={WAF_POSTURE_TABS.map((tab) => ({ id: tab.id, label: tab.label }))}
              onChange={setWafPostureTab}
              className="tabs-wrap"
            />
          ) : null}
          {(route !== 'waf-posture' || wafPostureTab === 'overview') ? (
            <Card>
              <CardHeader><CardTitle>{route === 'remediation' ? 'Create action item' : 'Create record'}</CardTitle><CardDescription>Route-specific create action backed by live backend APIs.</CardDescription></CardHeader>
              <CardContent>{renderCreateForm()}</CardContent>
            </Card>
          ) : null}
          {route === 'remediation' ? (
            <Card>
              <CardHeader>
                <CardTitle>Connector delivery preview</CardTitle>
                <CardDescription>Safe dry-run delivery through `POST /v1/waf/action-items/:id/deliver` with channel and connector fields.</CardDescription>
              </CardHeader>
              <CardContent className="product-form">
                <label><span>Action item</span>
                  <select value={selectedActionItemId || getString(data.wafActionItems[0] ?? {}, ['action_item_id', 'id'], '')} onChange={(event) => setSelectedActionItemId(event.target.value)}>
                    <option value="">Select action item</option>
                    {data.wafActionItems.map((item) => {
                      const id = getString(item, ['action_item_id', 'id'], '');
                      return <option key={id} value={id}>{getString(item, ['title', 'id'])}</option>;
                    })}
                  </select>
                </label>
                <label><span>Channel / connector</span>
                  <select value={deliverChannel} onChange={(event) => setDeliverChannel(event.target.value)}>
                    {REMEDIATION_CHANNELS.map((channel) => <option key={channel} value={channel}>{channel}</option>)}
                  </select>
                </label>
                <div className="form-actions full">
                  <Button
                    disabled={busy !== '' || data.wafActionItems.length === 0}
                    onClick={() => {
                      const actionItemId = selectedActionItemId || getString(data.wafActionItems[0] ?? {}, ['action_item_id', 'id'], '');
                      if (!actionItemId) {
                        setError('Select an action item before delivering.');
                        return;
                      }
                      void handleAction(`deliver-${actionItemId}`, () => requestJson(config, session, `/v1/waf/action-items/${actionItemId}/deliver`, {
                        method: 'POST',
                        body: { channel: deliverChannel, connector: deliverChannel, dry_run: true }
                      }), 'Dry-run deliver preview generated.');
                    }}
                  >
                    Dry-run deliver
                  </Button>
                </div>
              </CardContent>
            </Card>
          ) : null}
          {route === 'waf-posture' && wafPostureTab === 'overview' ? (
            <Card>
              <CardHeader><CardTitle>Coverage summary</CardTitle><CardDescription>From `/v1/waf/coverage`.</CardDescription></CardHeader>
              <CardContent className="factor-list">
                {['protected', 'underprotected', 'unprotected', 'unknown', 'excluded'].map((status) => {
                  const count = getNumber(data.wafCoverage ?? {}, [status]);
                  const percent = getNestedNumber(data.wafCoverage, ['percentages', status], 0);
                  return (
                    <div className="factor" key={status}>
                      <div><strong>{status}</strong><span>{count} assets</span></div>
                      <Badge tone={status === 'protected' ? scoreTone(percent) : count > 0 ? 'warn' : 'muted'}>{Math.round(percent)}%</Badge>
                      <Progress value={percent} />
                    </div>
                  );
                })}
              </CardContent>
            </Card>
          ) : null}
          {route === 'waf-posture' && wafPostureTab === 'overview' ? renderWafOperatorPanels() : null}
          {route === 'waf-posture' && wafPostureTab === 'roadmap' ? renderWafRoadmapPanel() : null}
          {route === 'waf-posture' && wafPostureTab === 'assets' ? (
            <Card>
              <CardHeader>
                <CardTitle>Declared assets</CardTitle>
                <CardDescription>Per-asset pass rate uses finalized validations in the last 30 days. Rule health appears when connector snapshots are available.</CardDescription>
              </CardHeader>
              <CardContent>
                <DataTable
                  columns={wafAssetColumns}
                  items={data.wafAssets}
                  empty={<EmptyState icon={ShieldCheck} title="No WAF assets recorded." body="Create a declared WAF asset or import from an approved connector snapshot." />}
                />
              </CardContent>
            </Card>
          ) : null}
          {route !== 'waf-posture' ? (
            <Card>
              <CardHeader><CardTitle>{ROUTE_BY_ID.get(route)?.label}</CardTitle><CardDescription>Live API records with triage actions.</CardDescription></CardHeader>
              <CardContent><DataTable columns={tableConfig.columns} items={tableConfig.items} empty={<EmptyState icon={ShieldCheck} title={tableConfig.emptyTitle} body={tableConfig.emptyBody} />} /></CardContent>
            </Card>
          ) : null}
          {output ? <Card><CardHeader><CardTitle>Action result</CardTitle></CardHeader><CardContent><pre className="codeblock">{output}</pre></CardContent></Card> : null}
        </>
      )}
      <DefensiveRulesPanel />
    </div>
  );
}