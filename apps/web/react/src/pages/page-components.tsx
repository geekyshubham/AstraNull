import { useEffect, useState, type FormEvent } from 'react';
import {
  Activity,
  Bot,
  CheckCircle2,
  ClipboardList,
  Clock3,
  FileCheck2,
  FileText,
  KeyRound,
  LifeBuoy,
  ListChecks,
  Network,
  PlugZap,
  RadioTower,
  ScanSearch,
  ServerCog,
  ShieldCheck,
  Siren,
  Target,
  TriangleAlert,
  UserCog,
  Users
} from 'lucide-react';
import { ReadinessGauge } from '../components/charts/readiness-gauge';
import { ScoreTrend } from '../components/charts/score-trend';
import { VectorHeatmap } from '../components/charts/vector-heatmap';
import { Badge } from '../components/ui/badge';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../components/ui/card';
import { EmptyState } from '../components/ui/empty-state';
import { Progress } from '../components/ui/progress';
import { DataTable, type TableColumn } from '../components/ui/table';
import { AnchorButton, Button } from '../components/ui/button';
import { Tabs } from '../components/ui/tabs';
import { buildApiHeaders, requestJson } from '../lib/api';
import { canAccessRoute } from '../lib/route-access';
import {
  ONBOARDING_HEARTBEAT_POLL_MS,
  ONBOARDING_PLACEMENT_TEST_CHECK_ID,
  agentHasRecentHeartbeat,
  extractPlacementDiagnosticsFromReadiness,
  placementTestComplete,
  resolveOnboardingHeartbeatState,
  summarizeOnboardingPlacementConfidenceHint
} from '../lib/onboarding';
import {
  authorizationArtifactPurpose,
  authorizationArtifactTitle,
  authorizationArtifactTypesForRequest,
  bestArtifactForType,
  buildLifecycleTimeline,
  buildMetadataArtifactUploadBody,
  explainArtifactReviewStatus,
  packRequirementForType
} from '../lib/high-scale';
import { resolveDashboardMetrics, resolveRecentRuns } from '../lib/dashboard-metrics';
import { buildEnvironmentReadinessRows } from '../lib/environments';
import { buildDetailHref } from '../lib/route-params';
import { DEFENSIVE_RULES, ROUTE_BY_ID } from '../lib/navigation';
import { routeTabs } from '../lib/prototype-manifest';
import type { DataItem, PortalConfig, PortalData, ReadinessFactor, RouteId, Session } from '../lib/types';
import { formatDate, formatExpectedBehavior, formatNumber, scoreTone } from '../lib/utils';

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

function featureEnabled(data: PortalData, key: 'waf_posture' | 'external_discovery' | 'connectors') {
  return Boolean(data.deploymentFeatures?.[key]);
}

export function PageHeader({ route, eyebrow }: { route: RouteId; eyebrow?: string }) {
  const item = ROUTE_BY_ID.get(route);
  return (
    <div className="page-head">
      <div>
        <p className="eyebrow">{eyebrow ?? item?.group}</p>
        <h2>{item?.label}</h2>
        <p>{item?.description}</p>
      </div>
    </div>
  );
}

export function MetricCard({
  label,
  value,
  sub,
  icon: Icon,
  tone = 'default'
}: {
  label: string;
  value: string | number;
  sub: string;
  icon: typeof Activity;
  tone?: 'default' | 'success' | 'warn' | 'danger' | 'info' | 'muted';
}) {
  return (
    <Card className="metric-card">
      <div className="metric-icon">
        <Icon size={18} />
      </div>
      <div>
        <span>{label}</span>
        <strong>{value}</strong>
        <p>{sub}</p>
      </div>
      <Badge tone={tone}>{tone === 'default' ? 'live' : tone}</Badge>
    </Card>
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
            <CheckCircle2 size={17} />
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

type DashboardTabId = 'overview' | 'business-services' | 'risk-trends' | 'evidence-feed';

function agentsForTargetGroup(data: PortalData, groupId: string) {
  return data.agents.filter((agent) => getString(agent, ['target_group_id']) === groupId);
}

function businessServiceRows(data: PortalData) {
  return data.targetGroups
    .filter((group) => group.archived_at == null)
    .map((group) => {
      const groupId = getString(group, ['id'], '');
      const boundAgents = agentsForTargetGroup(data, groupId);
      const onlineAgents = boundAgents.filter((agent) => getString(agent, ['status']) === 'online').length;
      const openFindings = data.findings.filter((finding) =>
        getString(finding, ['target_group_id']) === groupId &&
        getString(finding, ['status'], 'open') === 'open'
      ).length;
      const completedRuns = data.runs.filter((run) =>
        getString(run, ['target_group_id']) === groupId &&
        ['completed', 'verdicted'].includes(getString(run, ['status']))
      ).length;
      return {
        group,
        groupId,
        boundAgents: boundAgents.length,
        onlineAgents,
        openFindings,
        completedRuns
      };
    });
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

export function DashboardPage({ data }: { data: PortalData }) {
  const [tab, setTab] = useState<DashboardTabId>('overview');
  const tabOptions = routeTabs('dashboard').map((item) => ({ id: item.id as DashboardTabId, label: item.label }));
  const score = typeof data.state?.readiness?.score === 'number' ? data.state.readiness.score : null;
  const factors = Array.isArray(data.state?.readiness?.factors) ? data.state.readiness.factors : [];
  const metrics = resolveDashboardMetrics(data);
  const recentRuns = resolveRecentRuns(data);
  const openFindingRows = data.findings
    .filter((finding) => getString(finding, ['status'], 'open') === 'open')
    .slice(0, 5);
  const agingFindings = [...data.findings]
    .filter((finding) => getString(finding, ['status'], 'open') === 'open')
    .sort((left, right) => String(left.created_at ?? left.id ?? '').localeCompare(String(right.created_at ?? right.id ?? '')))
    .slice(0, 8);
  const recentEvidence = [...data.evidence].slice(-5).reverse();
  const evidenceFeed = evidenceFeedRows(data);
  const businessServices = businessServiceRows(data);
  const pendingHighScale = data.highScale
    .filter((request) => ['submitted', 'under_review', 'approved', 'scheduled'].includes(getString(request, ['state'])))
    .slice(0, 5);
  const businessServiceColumns: TableColumn<ReturnType<typeof businessServiceRows>[number]>[] = [
    {
      key: 'name',
      label: 'Service',
      render: (row) => getString(row.group, ['name', 'id'])
    },
    {
      key: 'environment',
      label: 'Environment',
      render: (row) => getString(row.group, ['environment_id'], 'unassigned')
    },
    {
      key: 'owner',
      label: 'Owner',
      render: (row) => getString(row.group, ['owner', 'owner_email'], 'unassigned')
    },
    {
      key: 'agents',
      label: 'Agents',
      render: (row) => `${row.onlineAgents}/${row.boundAgents} online`
    },
    {
      key: 'runs',
      label: 'Runs',
      render: (row) => String(row.completedRuns)
    },
    {
      key: 'findings',
      label: 'Open findings',
      render: (row) => String(row.openFindings)
    },
    {
      key: 'actions',
      label: '',
      render: (row) => (
        <AnchorButton size="sm" variant="secondary" href={buildDetailHref('target-group-detail', row.groupId)}>
          Open
        </AnchorButton>
      )
    }
  ];

  return (
    <div className="content">
      <PageHeader route="dashboard" eyebrow="Readiness command center" />
      <Tabs value={tab} options={tabOptions} onChange={setTab} className="tabs-wrap" />
      {tab === 'overview' ? (
        <>
          <div className="dashboard-grid">
            <Card className="score-card">
              <CardHeader>
                <CardTitle>Readiness score</CardTitle>
                <CardDescription>Evidence-backed score across declared targets.</CardDescription>
              </CardHeader>
              <CardContent>
                {score === null ? (
                  <EmptyState
                    icon={Activity}
                    title="Readiness state unavailable."
                    body="The dashboard is waiting for `/v1/state` to return an evidence-backed readiness score."
                  />
                ) : (
                  <ReadinessGauge score={score} />
                )}
              </CardContent>
            </Card>
            <div className="metric-grid">
              <MetricCard label="Target groups" value={metrics.targetGroups} sub="Customer-declared scope" icon={Target} tone="info" />
              <MetricCard label="Agents online" value={metrics.agentsOnline} sub="Outbound-only observers" icon={Bot} tone="success" />
              <MetricCard label="Open findings" value={metrics.openFindings} sub="Evidence-backed gaps" icon={TriangleAlert} tone={metrics.openFindings > 0 ? 'warn' : 'success'} />
              <MetricCard label="High-scale" value={metrics.highScaleRequests} sub="SOC-gated requests" icon={ShieldCheck} tone="muted" />
            </div>
          </div>
          <div className="split">
            <Card>
              <CardHeader>
                <CardTitle>Weighted factors</CardTitle>
                <CardDescription>No factor can pass without supporting evidence.</CardDescription>
              </CardHeader>
              <CardContent className="factor-list">
                {factors.length === 0 ? (
                  <EmptyState
                    icon={FileCheck2}
                    title="No readiness factors returned."
                    body="Factors appear after `/v1/state` publishes evidence-backed scoring inputs."
                  />
                ) : (
                  factors.map((factor: ReadinessFactor) => {
                    const value = Math.round(factor.score ?? 0);
                    return (
                      <div className="factor" key={factor.key ?? factor.label}>
                        <div>
                          <strong>{factor.label ?? factor.key}</strong>
                          <span>{factor.reason ?? factor.detail ?? 'Awaiting evidence.'}</span>
                        </div>
                        <Badge tone={scoreTone(value)}>{value}%</Badge>
                        <Progress value={value} />
                      </div>
                    );
                  })
                )}
              </CardContent>
            </Card>
            <Card>
              <CardHeader>
                <CardTitle>Vector coverage matrix</CardTitle>
                <CardDescription>Coverage by vector family and declared target group.</CardDescription>
              </CardHeader>
              <CardContent>
                <VectorHeatmap
                  checks={data.checks}
                  targetGroups={data.targetGroups}
                  testPolicies={data.testPolicies}
                  runs={data.runs}
                  evidence={data.evidence}
                />
              </CardContent>
            </Card>
          </div>
          <div className="split">
            <Card>
              <CardHeader>
                <CardTitle>Recent test runs</CardTitle>
                <CardDescription>Latest bounded validation activity with links to run detail.</CardDescription>
              </CardHeader>
              <CardContent>
                {recentRuns.length === 0 ? (
                  <EmptyState icon={ListChecks} title="No test runs yet." body="Start a safe validation from Onboarding or Test Runs." actionLabel="Open onboarding" actionHref="#onboarding" />
                ) : (
                  <ul className="dashboard-link-list">
                    {recentRuns.map((run) => {
                      const id = getString(run, ['id'], '');
                      return (
                        <li key={id}>
                          <div>
                            <strong>{id}</strong>
                            <span>{getString(run, ['status'])} · {getString(run, ['check_id'])}</span>
                          </div>
                          <AnchorButton size="sm" variant="secondary" href={buildDetailHref('run-detail', id)}>Open</AnchorButton>
                        </li>
                      );
                    })}
                  </ul>
                )}
              </CardContent>
            </Card>
            <Card>
              <CardHeader>
                <CardTitle>Open findings</CardTitle>
                <CardDescription>Evidence-backed gaps that still need triage or remediation.</CardDescription>
              </CardHeader>
              <CardContent>
                {openFindingRows.length === 0 ? (
                  <EmptyState icon={TriangleAlert} title="No open findings." body="Findings appear after validation runs produce evidence-backed gaps." actionLabel="Open findings" actionHref="#findings" />
                ) : (
                  <ul className="dashboard-link-list">
                    {openFindingRows.map((finding) => {
                      const id = getString(finding, ['id'], '');
                      return (
                        <li key={id}>
                          <div>
                            <strong>{getString(finding, ['title', 'id'])}</strong>
                            <span>{getString(finding, ['severity'])} · {getString(finding, ['assignee'], 'unassigned')}</span>
                          </div>
                          <AnchorButton size="sm" variant="secondary" href="#findings">Triage</AnchorButton>
                        </li>
                      );
                    })}
                  </ul>
                )}
              </CardContent>
            </Card>
          </div>
          <div className="split">
            <Card>
              <CardHeader>
                <CardTitle>Recent evidence</CardTitle>
                <CardDescription>Latest vault records correlated to runs and findings.</CardDescription>
              </CardHeader>
              <CardContent>
                {recentEvidence.length === 0 ? (
                  <EmptyState icon={FileCheck2} title="No evidence records yet." body="Evidence appears after validation runs complete and observations are correlated." actionLabel="Open evidence" actionHref="#evidence" />
                ) : (
                  <ul className="dashboard-link-list">
                    {recentEvidence.map((item) => {
                      const id = getString(item, ['id'], '');
                      return (
                        <li key={id}>
                          <div>
                            <strong>{id}</strong>
                            <span>{getString(item, ['kind', 'type'])} · {formatDate(item.created_at)}</span>
                          </div>
                          <AnchorButton size="sm" variant="secondary" href="#evidence">Inspect</AnchorButton>
                        </li>
                      );
                    })}
                  </ul>
                )}
              </CardContent>
            </Card>
            <Card>
              <CardHeader>
                <CardTitle>High-scale / SOC requests</CardTitle>
                <CardDescription>Customers submit requests only — SOC executes after approval.</CardDescription>
              </CardHeader>
              <CardContent>
                {pendingHighScale.length === 0 ? (
                  <EmptyState icon={ShieldCheck} title="No pending high-scale requests." body="Governed high-scale intake appears after customers submit authorization packs." actionLabel="Open high-scale" actionHref="#high-scale" />
                ) : (
                  <ul className="dashboard-link-list">
                    {pendingHighScale.map((request) => {
                      const id = getString(request, ['id'], '');
                      return (
                        <li key={id}>
                          <div>
                            <strong>{id}</strong>
                            <span>{getString(request, ['state'])} · {getString(request, ['target_group_id'])}</span>
                          </div>
                          <AnchorButton size="sm" variant="secondary" href="#high-scale">View</AnchorButton>
                        </li>
                      );
                    })}
                  </ul>
                )}
              </CardContent>
            </Card>
          </div>
          <DefensiveRulesPanel />
        </>
      ) : null}
      {tab === 'business-services' ? (
        <Card>
          <CardHeader>
            <CardTitle>Business services</CardTitle>
            <CardDescription>Declared target groups mapped to environment, owner, and current validation posture.</CardDescription>
          </CardHeader>
          <CardContent>
            <DataTable
              columns={businessServiceColumns}
              items={businessServices}
              empty={(
                <EmptyState
                  icon={Target}
                  title="No declared target groups yet."
                  body="Create a target group to map business services to validation scope."
                  actionLabel="Open target groups"
                  actionHref="#target-groups"
                />
              )}
            />
          </CardContent>
        </Card>
      ) : null}
      {tab === 'risk-trends' ? (
        <div className="split">
          <Card>
            <CardHeader>
              <CardTitle>Readiness trend</CardTitle>
              <CardDescription>Score trajectory derived from bounded validation run history.</CardDescription>
            </CardHeader>
            <CardContent>
              {score === null ? (
                <EmptyState icon={Activity} title="Readiness score unavailable." body="Trend appears after `/v1/state` publishes an evidence-backed score." />
              ) : (
                <ScoreTrend runs={data.runs} currentScore={score} />
              )}
            </CardContent>
          </Card>
          <Card>
            <CardHeader>
              <CardTitle>Vector coverage matrix</CardTitle>
              <CardDescription>Coverage by vector family and declared target group.</CardDescription>
            </CardHeader>
            <CardContent>
              <VectorHeatmap
                checks={data.checks}
                targetGroups={data.targetGroups}
                testPolicies={data.testPolicies}
                runs={data.runs}
                evidence={data.evidence}
              />
            </CardContent>
          </Card>
          <Card>
            <CardHeader>
              <CardTitle>Aging open findings</CardTitle>
              <CardDescription>Oldest open gaps that still pressure readiness.</CardDescription>
            </CardHeader>
            <CardContent>
              {agingFindings.length === 0 ? (
                <EmptyState icon={TriangleAlert} title="No open findings." body="Open findings appear after validation runs produce evidence-backed gaps." actionLabel="Open findings" actionHref="#findings" />
              ) : (
                <ul className="dashboard-link-list">
                  {agingFindings.map((finding) => {
                    const id = getString(finding, ['id'], '');
                    return (
                      <li key={id}>
                        <div>
                          <strong>{getString(finding, ['title', 'id'])}</strong>
                          <span>{getString(finding, ['severity'])} · opened {formatDate(finding.created_at)}</span>
                        </div>
                        <AnchorButton size="sm" variant="secondary" href="#findings">Triage</AnchorButton>
                      </li>
                    );
                  })}
                </ul>
              )}
            </CardContent>
          </Card>
        </div>
      ) : null}
      {tab === 'evidence-feed' ? (
        <Card>
          <CardHeader>
            <CardTitle>Evidence feed</CardTitle>
            <CardDescription>Newest evidence vault records and custody-related audit activity.</CardDescription>
          </CardHeader>
          <CardContent>
            {evidenceFeed.length === 0 ? (
              <EmptyState
                icon={FileCheck2}
                title="No evidence or custody activity yet."
                body="Evidence and custody events appear after validation runs complete and exports are verified."
                actionLabel="Open evidence"
                actionHref="#evidence"
              />
            ) : (
              <ul className="dashboard-link-list">
                {evidenceFeed.map((item) => (
                  <li key={`${item.source}-${item.id}`}>
                    <div>
                      <strong>{item.id}</strong>
                      <span>{item.kind} · {item.source} · {formatDate(item.created_at)}</span>
                    </div>
                    <AnchorButton size="sm" variant="secondary" href={item.source === 'audit' ? '#audit' : '#evidence'}>
                      Inspect
                    </AnchorButton>
                  </li>
                ))}
              </ul>
            )}
          </CardContent>
        </Card>
      ) : null}
    </div>
  );
}

export function OnboardingPage({
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
  const [heartbeatSkipped, setHeartbeatSkipped] = useState(false);
  const [pollStartedAt, setPollStartedAt] = useState<number | null>(null);
  const [polledAgents, setPolledAgents] = useState<DataItem[] | null>(null);
  const firstGroup = data.targetGroups[0] ?? null;
  const firstTargetId = getString(firstGroup ?? {}, ['first_target_id'], '');
  const safeCheck = data.checks.find((check) => getString(check, ['safety_class']) === 'safe') ?? data.checks[0] ?? null;
  const placementDiagnostics = extractPlacementDiagnosticsFromReadiness(data.state?.readiness as DataItem | undefined);
  const agentsForHeartbeat = polledAgents ?? data.agents;
  const heartbeatState = resolveOnboardingHeartbeatState(agentsForHeartbeat, {
    pollStartedAt: pollStartedAt ?? undefined
  });
  const placementHint = summarizeOnboardingPlacementConfidenceHint(
    heartbeatState.agents[0] ?? agentsForHeartbeat[0] ?? null,
    placementDiagnostics
  );
  const placementDone = placementTestComplete(data.runs);
  const heartbeatVerified = heartbeatSkipped
    || agentsForHeartbeat.some((agent) => agentHasRecentHeartbeat(agent));
  const steps = [
    ['Environment', data.targetGroups.length > 0],
    ['Target group', data.targetGroups.length > 0],
    ['Bootstrap token', data.bootstrapTokens.length > 0 || Boolean(tokenSecret)],
    ['Agent heartbeat', heartbeatVerified],
    ['Placement test', placementDone],
    ['First safe run', data.runs.some((run) =>
      getString(run, ['check_id']) !== ONBOARDING_PLACEMENT_TEST_CHECK_ID
      && ['completed', 'verdicted', 'running'].includes(getString(run, ['status']))
    )]
  ] as const;

  const shouldPollHeartbeat = Boolean(tokenSecret || data.bootstrapTokens.length > 0)
    && !heartbeatSkipped
    && heartbeatState.status !== 'online'
    && heartbeatState.status !== 'timeout';

  useEffect(() => {
    if (!shouldPollHeartbeat) return undefined;
    const startedAt = pollStartedAt ?? Date.now();
    if (pollStartedAt === null) setPollStartedAt(startedAt);

    async function pollAgents() {
      try {
        const payload = await requestJson(config, session, '/v1/agents') as { items?: DataItem[] };
        const items = Array.isArray(payload.items) ? payload.items : [];
        setPolledAgents(items);
        const state = resolveOnboardingHeartbeatState(items, { pollStartedAt: startedAt });
        if (state.status === 'online' || state.status === 'timeout') {
          await onRefresh();
        }
      } catch {
        /* keep polling until timeout */
      }
    }

    void pollAgents();
    const timer = window.setInterval(() => {
      void pollAgents();
    }, ONBOARDING_HEARTBEAT_POLL_MS);
    return () => window.clearInterval(timer);
  }, [config, session, onRefresh, pollStartedAt, shouldPollHeartbeat]);

  async function runOnboardingAction<T>(label: string, action: () => Promise<T>, success: string) {
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
      setError(payload?.message ?? payload?.error ?? (err instanceof Error ? err.message : 'Onboarding action failed.'));
      return null;
    } finally {
      setBusy('');
    }
  }

  async function handleCreateScope(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const created = await runOnboardingAction('onboard-create-group', async () => {
      const group = await requestJson(config, session, '/v1/target-groups', {
        method: 'POST',
        body: {
          name: String(form.get('name') ?? 'Onboarding group').trim(),
          environment_id: String(form.get('environment_id') ?? 'env_onboarding').trim(),
          expected_behavior_default: 'must_block_before_origin',
          timezone: 'UTC'
        }
      }) as DataItem;
      const groupId = getString(group, ['id'], '');
      if (String(form.get('target_value') ?? '').trim()) {
        await requestJson(config, session, `/v1/target-groups/${groupId}/targets`, {
          method: 'POST',
          body: {
            kind: 'fqdn',
            value: String(form.get('target_value') ?? '').trim(),
            expected_behavior: 'must_block_before_origin'
          }
        });
      }
      return group;
    }, 'Declared target group and optional first target created.');
    if (created) event.currentTarget.reset();
  }

  async function createBootstrapToken() {
    const created = await runOnboardingAction('onboard-create-token', () => requestJson(config, session, '/v1/bootstrap-tokens', {
      method: 'POST',
      body: {
        name: 'onboarding-install',
        environment_id: getString(firstGroup, ['environment_id'], 'env_demo'),
        ...(getString(firstGroup, ['id'], '') ? { target_group_id: getString(firstGroup, ['id'], '') } : {}),
        expires_at: new Date(Date.now() + 60 * 60 * 1000).toISOString(),
        max_registrations: 1
      }
    }), 'Bootstrap token created. Copy the one-time secret now.');
    const secret = getString(created as DataItem, ['secret'], getNestedString(created as DataItem, ['token', 'secret'], ''));
    if (secret) setTokenSecret(secret);
  }

  async function resolveFirstTargetId(targetGroupId: string) {
    let targetId = firstTargetId;
    if (!targetId) {
      const detail = await requestJson(config, session, `/v1/target-groups/${targetGroupId}`) as DataItem;
      const targets = Array.isArray(detail.targets) ? detail.targets as DataItem[] : [];
      targetId = getString(targets[0] ?? {}, ['id'], '');
    }
    return targetId;
  }

  async function handleStartRun() {
    const targetGroupId = getString(firstGroup, ['id'], '');
    const checkId = getString(safeCheck ?? {}, ['check_id'], '');
    if (!targetGroupId || !checkId) {
      setError('Create a target group and ensure a safe check exists before starting a run.');
      return;
    }
    const targetId = await resolveFirstTargetId(targetGroupId);
    if (!targetId) {
      setError('Add at least one declared target before starting a safe validation run.');
      return;
    }
    await runOnboardingAction('onboard-start-run', () => requestJson(config, session, '/v1/test-runs', {
      method: 'POST',
      body: { target_group_id: targetGroupId, target_id: targetId, check_id: checkId }
    }), 'Safe validation run started from onboarding.');
  }

  async function handleStartPlacementTest() {
    const targetGroupId = getString(firstGroup, ['id'], '');
    if (!targetGroupId) {
      setError('Create a target group before starting the placement test.');
      return;
    }
    const targetId = await resolveFirstTargetId(targetGroupId);
    if (!targetId) {
      setError('Add at least one declared target before starting the placement test.');
      return;
    }
    await runOnboardingAction('onboard-start-placement-test', () => requestJson(config, session, '/v1/test-runs', {
      method: 'POST',
      body: {
        target_group_id: targetGroupId,
        target_id: targetId,
        check_id: ONBOARDING_PLACEMENT_TEST_CHECK_ID
      }
    }), 'Placement test run started — inspect observations on Test Runs when complete.');
  }

  const installToken = tokenSecret || '<BOOTSTRAP_TOKEN>';
  const heartbeatSeconds = Math.floor((heartbeatState.elapsedMs ?? 0) / 1000);
  return (
    <div className="content">
      <PageHeader route="onboarding" eyebrow="Guided setup" />
      {(message || error) && <div className={error ? 'form-banner error' : 'form-banner'}>{error || message}</div>}
      <Card>
        <CardHeader>
          <CardTitle>First validation path</CardTitle>
          <CardDescription>One environment, one target group, one outbound agent, one bounded validation run.</CardDescription>
        </CardHeader>
        <CardContent className="step-grid">
          {steps.map(([label, complete], index) => (
            <div className={complete ? 'step-card done' : 'step-card'} key={label}>
              <span>{complete ? <CheckCircle2 size={16} /> : index + 1}</span>
              <strong>{label}</strong>
              <p>{complete ? 'Evidence present' : 'Needs setup'}</p>
            </div>
          ))}
        </CardContent>
      </Card>
      <div className="split">
        <Card>
          <CardHeader>
            <CardTitle>Create declared scope</CardTitle>
            <CardDescription>Step 1: create the first target group and optional FQDN target.</CardDescription>
          </CardHeader>
          <CardContent>
            <form className="product-form" onSubmit={handleCreateScope}>
              <label><span>Group name</span><input name="name" defaultValue="Onboarding origin group" required /></label>
              <label><span>Environment ID</span><input name="environment_id" defaultValue="env_onboarding" required /></label>
              <label className="full"><span>First target (optional)</span><input name="target_value" placeholder="origin.example.com" /></label>
              <div className="form-actions full"><Button type="submit" disabled={busy !== ''}>Create target group</Button></div>
            </form>
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>Bootstrap token and safe run</CardTitle>
            <CardDescription>Step 2–3: issue install token, then start the first bounded validation run.</CardDescription>
          </CardHeader>
          <CardContent className="product-form">
            <Button disabled={busy !== ''} onClick={() => void createBootstrapToken()}>Create bootstrap token</Button>
            <Button variant="secondary" disabled={busy !== '' || !firstGroup || !safeCheck} onClick={() => void handleStartRun()}>Start safe validation run</Button>
            <pre className="codeblock">{`curl -fsSL ${typeof window !== 'undefined' ? window.location.origin : ''}/agents/install.sh \\
  | sudo ASTRANULL_API_URL="${typeof window !== 'undefined' ? window.location.origin : ''}" \\
       ASTRANULL_BOOTSTRAP_TOKEN="${installToken}" bash`}</pre>
            {tokenSecret ? <p className="muted">One-time token shown. It will not be displayed again after refresh.</p> : null}
          </CardContent>
        </Card>
      </div>
      <Card>
        <CardHeader>
          <CardTitle>Agent heartbeat verification</CardTitle>
          <CardDescription>Polls <code>GET /v1/agents</code> every {ONBOARDING_HEARTBEAT_POLL_MS / 1000}s after a bootstrap token is issued.</CardDescription>
        </CardHeader>
        <CardContent>
          {heartbeatState.status === 'online' ? (
            <div className="onboarding-heartbeat-panel onboarding-heartbeat-panel--online">
              <p className="onboarding-heartbeat-status onboarding-heartbeat-status--online">
                Agent online — last heartbeat {getString(heartbeatState.agents[0] ?? {}, ['last_heartbeat_at'], 'received')}.
              </p>
              <p className="muted onboarding-placement-hint"><strong>Placement confidence:</strong> {placementHint}</p>
              <p className="muted">Proceed to the optional placement test or start the first safe validation.</p>
            </div>
          ) : heartbeatState.status === 'timeout' ? (
            <div className="onboarding-heartbeat-panel onboarding-heartbeat-panel--timeout">
              <EmptyState
                icon={Clock3}
                title="Heartbeat timeout reached."
                body="No fresh agent heartbeat was observed within the onboarding window. Continue without an agent or regenerate the bootstrap token."
              />
              {!heartbeatSkipped ? (
                <div className="form-actions">
                  <Button variant="secondary" disabled={busy !== ''} onClick={() => setHeartbeatSkipped(true)}>Continue without agent</Button>
                </div>
              ) : null}
            </div>
          ) : (
            <div className="onboarding-heartbeat-panel onboarding-heartbeat-panel--waiting">
              <p className="onboarding-heartbeat-status onboarding-heartbeat-status--waiting" aria-live="polite">
                <span className="onboarding-heartbeat-spinner" aria-hidden="true" />
                {heartbeatState.status === 'stale'
                  ? 'Agent registered but heartbeat is stale — waiting for a fresh heartbeat…'
                  : 'Waiting for agent heartbeat…'}
              </p>
              <p className="muted">Polling <code>GET /v1/agents</code> every {ONBOARDING_HEARTBEAT_POLL_MS / 1000}s (elapsed {heartbeatSeconds}s).</p>
              <p className="muted onboarding-placement-hint"><strong>Placement confidence:</strong> {placementHint}</p>
              <div className="row-actions onboarding-troubleshoot">
                <span className="muted">Agent not connecting?</span>
                <AnchorButton size="sm" variant="secondary" href="#agents">Open Agents</AnchorButton>
                <AnchorButton size="sm" variant="secondary" href="#settings">Regenerate token</AnchorButton>
              </div>
            </div>
          )}
        </CardContent>
      </Card>
      <Card>
        <CardHeader>
          <CardTitle>Placement test</CardTitle>
          <CardDescription>Runs a bounded protected-path canary check (<code>{ONBOARDING_PLACEMENT_TEST_CHECK_ID}</code>) — metadata only, no exploit payloads.</CardDescription>
        </CardHeader>
        <CardContent className="product-form">
          {placementDone ? (
            <p className="muted onboarding-placement-done">Placement test run started — inspect observations on Test Runs when complete.</p>
          ) : (
            <>
              <Button disabled={busy !== '' || !firstGroup} onClick={() => void handleStartPlacementTest()}>Start placement test</Button>
              <p className="muted">Optional — skip if you will run the first safe validation immediately after heartbeat verification.</p>
            </>
          )}
          <div className="callout-list">
            <div className="callout info"><RadioTower size={18} /><span>Install where the agent can observe target traffic.</span></div>
            <div className="callout warn"><Clock3 size={18} /><span>Run a safe canary before relying on verdicts.</span></div>
            <div className="callout"><FileCheck2 size={18} /><span>Evidence vault records the placement signal.</span></div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

export function TargetGroupsPage({
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
  const [selectedId, setSelectedId] = useState(() => getString(data.targetGroups[0] ?? {}, ['id'], ''));
  const [selectedTargetId, setSelectedTargetId] = useState('');
  const [detail, setDetail] = useState<DataItem | null>(null);
  const [busy, setBusy] = useState('');
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');
  const environments = [...new Set(data.targetGroups.map((group) => getString(group, ['environment_id'], '')).filter(Boolean))];
  const activeGroup = data.targetGroups.find((group) => getString(group, ['id'], '') === selectedId) ?? data.targetGroups[0] ?? null;
  const effectiveGroupId = getString(activeGroup ?? {}, ['id'], selectedId);
  const targets = Array.isArray(detail?.targets) ? detail.targets as DataItem[] : [];

  useEffect(() => {
    const firstId = getString(data.targetGroups[0] ?? {}, ['id'], '');
    if (!selectedId && firstId) setSelectedId(firstId);
  }, [data.targetGroups, selectedId]);

  useEffect(() => {
    if (!effectiveGroupId) {
      setDetail(null);
      return;
    }
    let cancelled = false;
    requestJson(config, session, `/v1/target-groups/${effectiveGroupId}`)
      .then((payload) => {
        if (!cancelled) setDetail(payload as DataItem);
      })
      .catch(() => {
        if (!cancelled) setDetail(null);
      });
    return () => {
      cancelled = true;
    };
  }, [config, session, effectiveGroupId]);

  const groupColumns: TableColumn<DataItem>[] = [
    { key: 'name', label: 'Group', render: (item) => getString(item, ['name', 'id']) },
    { key: 'env', label: 'Environment', render: (item) => getString(item, ['environment_id']) },
    { key: 'behavior', label: 'Expected behavior', render: (item) => formatExpectedBehavior(getString(item, ['expected_behavior_default'], '')) },
    { key: 'timezone', label: 'Timezone', render: (item) => getString(item, ['timezone']) },
    { key: 'created', label: 'Created', render: (item) => formatDate(item.created_at) },
    {
      key: 'actions',
      label: 'Actions',
      render: (item) => {
        const id = getString(item, ['id'], '');
        return (
          <div className="row-actions">
            <Button size="sm" variant={id === effectiveGroupId ? 'default' : 'secondary'} onClick={() => setSelectedId(id)}>Open</Button>
            <AnchorButton size="sm" variant="ghost" href={buildDetailHref('target-group-detail', id)}>Detail</AnchorButton>
            <Button size="sm" variant="danger" disabled={busy !== ''} onClick={() => void archiveTargetGroup(id)}>Archive target group</Button>
          </div>
        );
      }
    }
  ];
  const selectedTarget = targets.find((target) => getString(target, ['id'], '') === selectedTargetId) ?? targets[0] ?? null;

  useEffect(() => {
    const firstTargetId = getString(targets[0] ?? {}, ['id'], '');
    if (!selectedTargetId && firstTargetId) setSelectedTargetId(firstTargetId);
    if (selectedTargetId && !targets.some((target) => getString(target, ['id'], '') === selectedTargetId)) {
      setSelectedTargetId(firstTargetId);
    }
  }, [targets, selectedTargetId]);

  const targetColumns: TableColumn<DataItem>[] = [
    { key: 'kind', label: 'Type', render: (item) => <Badge tone="info">{getString(item, ['kind'])}</Badge> },
    { key: 'value', label: 'Target', render: (item) => getString(item, ['value']) },
    { key: 'expected', label: 'Expected behavior', render: (item) => formatExpectedBehavior(getString(item, ['expected_behavior'], '')) },
    { key: 'created', label: 'Created', render: (item) => formatDate(item.created_at) },
    {
      key: 'actions',
      label: 'Actions',
      render: (item) => {
        const id = getString(item, ['id'], '');
        return (
          <div className="row-actions">
            <Button size="sm" variant={id === selectedTargetId ? 'default' : 'secondary'} onClick={() => setSelectedTargetId(id)}>Edit</Button>
            <AnchorButton size="sm" variant="ghost" href={buildDetailHref('target-group-detail', effectiveGroupId)}>Detail</AnchorButton>
          </div>
        );
      }
    }
  ];

  async function runTargetAction<T>(label: string, action: () => Promise<T>, success: string) {
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
      setError(payload?.message ?? payload?.error ?? (err instanceof Error ? err.message : 'Action failed.'));
      return null;
    } finally {
      setBusy('');
    }
  }

  async function refreshDetail(id = effectiveGroupId) {
    if (!id) return;
    const payload = await requestJson(config, session, `/v1/target-groups/${id}`);
    setDetail(payload as DataItem);
  }

  async function handleCreateGroup(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const formElement = event.currentTarget;
    const form = new FormData(formElement);
    const name = String(form.get('name') ?? '').trim();
    if (!name) {
      setError('Target group name is required.');
      return;
    }
    const created = await runTargetAction('create-target-group', () => requestJson(config, session, '/v1/target-groups', {
      method: 'POST',
      body: {
        name,
        environment_id: String(form.get('environment_id') ?? 'prod').trim() || 'prod',
        description: String(form.get('description') ?? '').trim(),
        expected_behavior_default: String(form.get('expected_behavior_default') ?? 'must_block_before_origin'),
        timezone: String(form.get('timezone') ?? 'UTC').trim() || 'UTC',
        safety_policy: {
          max_concurrent_runs: Number(form.get('max_concurrent_runs') ?? 1),
          min_seconds_between_runs: Number(form.get('min_seconds_between_runs') ?? 300)
        }
      }
    }), 'Target group created from declared customer scope.');
    if (created && typeof created === 'object' && 'id' in created) {
      const id = String((created as { id: string }).id);
      setSelectedId(id);
      formElement.reset();
      await refreshDetail(id);
    }
  }

  async function handleAddTarget(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!effectiveGroupId) {
      setError('Create or select a target group before adding a target.');
      return;
    }
    const formElement = event.currentTarget;
    const form = new FormData(formElement);
    const value = String(form.get('value') ?? '').trim();
    if (!value) {
      setError('Target value is required.');
      return;
    }
    await runTargetAction(`add-target-${effectiveGroupId}`, () => requestJson(config, session, `/v1/target-groups/${effectiveGroupId}/targets`, {
      method: 'POST',
      body: {
        kind: String(form.get('kind') ?? 'fqdn'),
        value,
        expected_behavior: String(form.get('expected_behavior') ?? getString(activeGroup ?? {}, ['expected_behavior_default'], 'must_block_before_origin'))
      }
    }), 'Declared target added to the selected group.');
    formElement.reset();
    await refreshDetail(effectiveGroupId);
  }

  async function handlePatchGroup(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!effectiveGroupId) return;
    const form = new FormData(event.currentTarget);
    await runTargetAction(`patch-target-group-${effectiveGroupId}`, () => requestJson(config, session, `/v1/target-groups/${effectiveGroupId}`, {
      method: 'PATCH',
      body: {
        name: String(form.get('name') ?? getString(activeGroup ?? {}, ['name'])).trim(),
        description: String(form.get('description') ?? '').trim(),
        expected_behavior_default: String(form.get('expected_behavior_default') ?? 'must_block_before_origin'),
        timezone: String(form.get('timezone') ?? 'UTC').trim() || 'UTC'
      }
    }), 'Target group settings saved.');
    await refreshDetail(effectiveGroupId);
  }

  async function archiveTargetGroup(id: string) {
    if (!id) return;
    if (!window.confirm('Archive this target group?')) return;
    await runTargetAction(`archive-target-group-${id}`, () => requestJson(config, session, `/v1/target-groups/${id}`, {
      method: 'DELETE'
    }), 'Target group archived.');
    if (selectedId === id) {
      setSelectedId('');
      setDetail(null);
    }
  }

  async function handlePatchTarget(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!effectiveGroupId || !selectedTargetId) {
      setError('Select a target before saving changes.');
      return;
    }
    const form = new FormData(event.currentTarget);
    await runTargetAction(`patch-target-${selectedTargetId}`, () => requestJson(config, session, `/v1/target-groups/${effectiveGroupId}/targets/${selectedTargetId}`, {
      method: 'PATCH',
      body: {
        kind: String(form.get('kind') ?? 'fqdn'),
        value: String(form.get('value') ?? '').trim(),
        expected_behavior: String(form.get('expected_behavior') ?? 'must_block_before_origin')
      }
    }), 'Declared target updated.');
    await refreshDetail(effectiveGroupId);
  }

  async function deleteTarget(targetId: string) {
    if (!effectiveGroupId || !targetId) return;
    if (!window.confirm('Delete this declared target?')) return;
    await runTargetAction(`delete-target-${targetId}`, () => requestJson(config, session, `/v1/target-groups/${effectiveGroupId}/targets/${targetId}`, {
      method: 'DELETE'
    }), 'Declared target deleted.');
    if (selectedTargetId === targetId) setSelectedTargetId('');
    await refreshDetail(effectiveGroupId);
  }

  return (
    <div className="content">
      <PageHeader route="target-groups" />
      <div className="metric-grid three">
        <MetricCard label="Declared groups" value={data.targetGroups.length} sub="Customer-provided scope only" icon={Target} tone="info" />
        <MetricCard label="Declared targets" value={targets.length} sub={effectiveGroupId ? 'Selected group detail' : 'Select a group'} icon={Network} tone="success" />
        <MetricCard label="Environments" value={environments.length} sub="Derived from target-group records" icon={ShieldCheck} tone="muted" />
      </div>
      {(message || error) && (
        <div className={error ? 'form-banner error' : 'form-banner'}>{error || message}</div>
      )}
      <div className="split">
        <Card>
          <CardHeader>
            <CardTitle>Create declared target group</CardTitle>
            <CardDescription>Customers declare scope manually. AstraNull does not discover inventory automatically.</CardDescription>
          </CardHeader>
          <CardContent>
            <form className="product-form" onSubmit={handleCreateGroup}>
              <label>
                <span>Name</span>
                <input name="name" placeholder="Retail Checkout - Production" required />
              </label>
              <label>
                <span>Environment</span>
                <input name="environment_id" placeholder="prod" defaultValue="prod" />
              </label>
              <label className="full">
                <span>Description</span>
                <textarea name="description" rows={3} placeholder="Business service, owner, and known protection context." />
              </label>
              <label>
                <span>Expected behavior</span>
                <select name="expected_behavior_default" defaultValue="must_block_before_origin">
                  <option value="must_block_before_origin">Must be blocked before origin</option>
                  <option value="must_allow_baseline_health">Must allow baseline health</option>
                  <option value="must_challenge_or_rate_limit">Must challenge or rate-limit</option>
                  <option value="must_not_expose_direct_ip">Must not expose direct IP</option>
                </select>
              </label>
              <label>
                <span>Timezone</span>
                <input name="timezone" defaultValue="UTC" />
              </label>
              <label>
                <span>Max concurrent runs</span>
                <input name="max_concurrent_runs" type="number" min="1" max="5" defaultValue="1" />
              </label>
              <label>
                <span>Cooldown seconds</span>
                <input name="min_seconds_between_runs" type="number" min="60" defaultValue="300" />
              </label>
              <div className="form-actions full">
                <Button type="submit" disabled={busy !== ''}>{busy === 'create-target-group' ? 'Creating...' : 'Create group'}</Button>
              </div>
            </form>
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>Add declared target</CardTitle>
            <CardDescription>Add FQDN, URL, IP/port, DNS, or canary targets to the selected group.</CardDescription>
          </CardHeader>
          <CardContent>
            <form className="product-form" onSubmit={handleAddTarget}>
              <label className="full">
                <span>Selected group</span>
                <select value={effectiveGroupId} onChange={(event) => setSelectedId(event.target.value)}>
                  {data.targetGroups.length === 0 ? <option value="">No target groups yet</option> : null}
                  {data.targetGroups.map((group) => (
                    <option key={getString(group, ['id'])} value={getString(group, ['id'])}>{getString(group, ['name', 'id'])}</option>
                  ))}
                </select>
              </label>
              <label>
                <span>Target type</span>
                <select name="kind" defaultValue="fqdn">
                  <option value="fqdn">FQDN</option>
                  <option value="url">URL</option>
                  <option value="ip_port">IP/Port</option>
                  <option value="dns">DNS service</option>
                  <option value="canary">Canary endpoint</option>
                </select>
              </label>
              <label>
                <span>Value</span>
                <input name="value" placeholder="checkout.example.com" required />
              </label>
              <label className="full">
                <span>Expected behavior</span>
                <select name="expected_behavior" defaultValue={getString(activeGroup ?? {}, ['expected_behavior_default'], 'must_block_before_origin')}>
                  <option value="must_block_before_origin">Must be blocked before origin</option>
                  <option value="must_allow_baseline_health">Must allow baseline health</option>
                  <option value="must_challenge_or_rate_limit">Must challenge or rate-limit</option>
                  <option value="must_not_expose_direct_ip">Must not expose direct IP</option>
                </select>
              </label>
              <div className="form-actions full">
                <Button type="submit" disabled={busy !== '' || !effectiveGroupId}>Add target</Button>
              </div>
            </form>
          </CardContent>
        </Card>
      </div>
      <Card>
        <CardHeader>
          <div>
            <CardTitle>Declared target groups</CardTitle>
            <CardDescription>All rows are tenant API records. Archived groups are removed from this active list.</CardDescription>
          </div>
          <Badge tone="info">{data.targetGroups.length} active</Badge>
        </CardHeader>
        <CardContent>
          <DataTable
            columns={groupColumns}
            items={data.targetGroups}
            empty={<EmptyState icon={Target} title="No target groups declared." body="Create the first business service or protected zone before running validation." />}
          />
        </CardContent>
      </Card>
      {activeGroup ? (
        <div className="split">
          <Card>
            <CardHeader>
              <CardTitle>Selected group settings</CardTitle>
              <CardDescription>Patch the declaration without changing any unrelated inventory automatically.</CardDescription>
            </CardHeader>
            <CardContent>
              <form key={effectiveGroupId} className="product-form" onSubmit={handlePatchGroup}>
                <label>
                  <span>Name</span>
                  <input name="name" defaultValue={getString(activeGroup, ['name'])} />
                </label>
                <label>
                  <span>Timezone</span>
                  <input name="timezone" defaultValue={getString(activeGroup, ['timezone'], 'UTC')} />
                </label>
                <label className="full">
                  <span>Description</span>
                  <textarea name="description" rows={3} defaultValue={getString(activeGroup, ['description'], '')} />
                </label>
                <label className="full">
                  <span>Default expected behavior</span>
                  <select name="expected_behavior_default" defaultValue={getString(activeGroup, ['expected_behavior_default'], 'must_block_before_origin')}>
                    <option value="must_block_before_origin">Must be blocked before origin</option>
                    <option value="must_allow_baseline_health">Must allow baseline health</option>
                    <option value="must_challenge_or_rate_limit">Must challenge or rate-limit</option>
                    <option value="must_not_expose_direct_ip">Must not expose direct IP</option>
                  </select>
                </label>
                <div className="form-actions full">
                  <Button type="submit" disabled={busy !== ''}>Save settings</Button>
                </div>
              </form>
            </CardContent>
          </Card>
          <Card>
            <CardHeader>
              <div>
                <CardTitle>Declared targets</CardTitle>
                <CardDescription>Target detail is loaded from `/v1/target-groups/{'{id}'}`.</CardDescription>
              </div>
              <Badge tone="success">{targets.length} targets</Badge>
            </CardHeader>
            <CardContent>
              <DataTable
                columns={targetColumns}
                items={targets}
                empty={<EmptyState icon={Network} title="No targets in this group." body="Add a declared target before safe validation runs can prove coverage." />}
              />
              {selectedTarget ? (
                <form key={selectedTargetId} className="product-form" onSubmit={handlePatchTarget}>
                  <label>
                    <span>Target type</span>
                    <select name="kind" defaultValue={getString(selectedTarget, ['kind'], 'fqdn')}>
                      <option value="fqdn">FQDN</option>
                      <option value="url">URL</option>
                      <option value="ip_port">IP/Port</option>
                      <option value="dns">DNS service</option>
                      <option value="canary">Canary endpoint</option>
                    </select>
                  </label>
                  <label className="full">
                    <span>Value</span>
                    <input name="value" defaultValue={getString(selectedTarget, ['value'], '')} required />
                  </label>
                  <label className="full">
                    <span>Expected behavior</span>
                    <select name="expected_behavior" defaultValue={getString(selectedTarget, ['expected_behavior'], 'must_block_before_origin')}>
                      <option value="must_block_before_origin">Must be blocked before origin</option>
                      <option value="must_allow_baseline_health">Must allow baseline health</option>
                      <option value="must_challenge_or_rate_limit">Must challenge or rate-limit</option>
                      <option value="must_not_expose_direct_ip">Must not expose direct IP</option>
                    </select>
                  </label>
                  <div className="form-actions full">
                    <Button type="submit" disabled={busy !== ''}>Save target</Button>
                    <Button type="button" variant="danger" disabled={busy !== ''} onClick={() => void deleteTarget(selectedTargetId)}>Delete target</Button>
                  </div>
                </form>
              ) : null}
            </CardContent>
          </Card>
        </div>
      ) : null}
    </div>
  );
}

export function ValidationPage({
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
  const source = route === 'checks' ? data.checks : route === 'runs' ? data.runs : route === 'findings' ? data.findings : data.evidence;
  const emptyIcon = route === 'findings' ? TriangleAlert : route === 'evidence' ? FileCheck2 : ListChecks;
  const firstGroup = data.targetGroups[0] ?? null;
  const safeCheck = data.checks.find((check) => getString(check, ['safety_class']) === 'safe') ?? null;

  async function runValidationAction<T>(label: string, action: () => Promise<T>, success: string) {
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
      setError(payload?.message ?? payload?.error ?? (err instanceof Error ? err.message : 'Validation action failed.'));
      return null;
    } finally {
      setBusy('');
    }
  }

  async function startSafeRun() {
    const targetGroupId = getString(firstGroup, ['id'], '');
    const checkId = getString(safeCheck ?? {}, ['check_id'], '');
    if (!targetGroupId || !checkId) {
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
    await runValidationAction('start-safe-run', () => requestJson(config, session, '/v1/test-runs', {
      method: 'POST',
      body: { target_group_id: targetGroupId, target_id: targetId, check_id: checkId }
    }), 'Safe validation run started.');
  }

  async function patchFinding(id: string, body: Record<string, unknown>, success: string) {
    if (!id) return;
    await runValidationAction(`finding-${id}`, () => requestJson(config, session, `/v1/findings/${id}`, {
      method: 'PATCH',
      body
    }), success);
  }

  const columns: TableColumn<DataItem>[] = [
    { key: 'name', label: 'Item', render: (item) => getString(item, ['name', 'title', 'check_id', 'id']) },
    { key: 'status', label: 'Status', render: (item) => <Badge tone={getString(item, ['status', 'verdict'], 'ready') === 'open' ? 'warn' : 'success'}>{getString(item, ['status', 'verdict'], 'ready')}</Badge> },
    { key: 'type', label: 'Type', render: (item) => getString(item, ['family', 'kind', 'severity', 'safety_class'], 'safe validation') },
    { key: 'time', label: 'Time', render: (item) => formatDate(item.created_at ?? item.started_at ?? item.updated_at) },
    ...(route === 'findings' ? [{
      key: 'actions',
      label: 'Actions',
      render: (item: DataItem) => {
        const id = getString(item, ['id'], '');
        return (
          <div className="row-actions">
            <Button size="sm" variant="secondary" disabled={busy !== ''} onClick={() => void patchFinding(id, { status: 'accepted_risk' }, 'Finding marked accepted risk.')}>Accept risk</Button>
            <Button size="sm" variant="ghost" disabled={busy !== ''} onClick={() => void patchFinding(id, { status: 'closed' }, 'Finding closed.')}>Close</Button>
          </div>
        );
      }
    }] as TableColumn<DataItem>[] : [])
  ];

  return (
    <div className="content">
      <PageHeader route={route} />
      <div className="metric-grid three">
        <MetricCard label="Checks" value={data.checks.length} sub="Bounded safe catalog" icon={ListChecks} tone="info" />
        <MetricCard label="Runs" value={data.runs.length} sub="Probe plus agent correlation" icon={Activity} tone="success" />
        <MetricCard label="Evidence" value={data.evidence.length} sub="Custody-ready records" icon={FileCheck2} tone="muted" />
      </div>
      {(message || error) && <div className={error ? 'form-banner error' : 'form-banner'}>{error || message}</div>}
      {route === 'runs' && (
        <Card>
          <CardHeader>
            <CardTitle>Start safe validation</CardTitle>
            <CardDescription>Creates a bounded run against the first declared target in the first active target group.</CardDescription>
          </CardHeader>
          <CardContent>
            <Button disabled={busy !== '' || !firstGroup || !safeCheck} onClick={() => void startSafeRun()}>
              {busy === 'start-safe-run' ? 'Starting...' : 'Start safe run'}
            </Button>
          </CardContent>
        </Card>
      )}
      <Card>
        <CardHeader>
          <CardTitle>{ROUTE_BY_ID.get(route)?.label}</CardTitle>
          <CardDescription>Verdicts should always explain what was observed and what evidence supports the outcome.</CardDescription>
        </CardHeader>
        <CardContent>
          <DataTable
            columns={columns}
            items={source}
            empty={<EmptyState icon={emptyIcon} title="No evidence-backed records yet." body="Run a safe validation after target group and agent setup. High-scale validation remains request-only for customers." actionLabel="Open onboarding" actionHref="#onboarding" />}
          />
        </CardContent>
      </Card>
    </div>
  );
}

export function GovernancePage({ route, data }: { route: RouteId; data: PortalData }) {
  const source =
    route === 'high-scale' ? data.highScale :
      route === 'notifications' ? data.notificationRules :
        route === 'audit' ? data.audit :
          route === 'release-evidence' ? data.releaseEvidence :
            data.runs;
  const columns: TableColumn<DataItem>[] = [
    { key: 'id', label: 'Record', render: (item) => getString(item, ['title', 'name', 'id']) },
    { key: 'state', label: 'State', render: (item) => <Badge tone={getString(item, ['status', 'state'], 'recorded') === 'open' ? 'warn' : 'muted'}>{getString(item, ['status', 'state'], 'recorded')}</Badge> },
    { key: 'owner', label: 'Owner', render: (item) => getString(item, ['owner', 'actor_id', 'requested_by', 'created_by'], 'AstraNull') },
    { key: 'time', label: 'Time', render: (item) => formatDate(item.created_at ?? item.updated_at) }
  ];
  return (
    <div className="content">
      <PageHeader route={route} />
      <div className="metric-grid three">
        <MetricCard label="High-scale requests" value={data.highScale.length} sub="SOC controls required" icon={ShieldCheck} tone="muted" />
        <MetricCard label="Release evidence" value={data.releaseEvidence.length} sub="Metadata-only inventory" icon={FileText} tone="info" />
        <MetricCard label="Audit entries" value={formatNumber(data.audit.length)} sub="Security-relevant actions" icon={FileCheck2} tone="success" />
      </div>
      <Card>
        <CardHeader>
          <CardTitle>{ROUTE_BY_ID.get(route)?.label}</CardTitle>
          <CardDescription>Governance actions favor approval artifacts, custody, and fail-closed access boundaries.</CardDescription>
        </CardHeader>
        <CardContent>
          <DataTable
            columns={columns}
            items={source}
            empty={<EmptyState icon={ShieldCheck} title="No governance records yet." body="Requests, approvals, reports, and audit records appear here after controlled workflow activity." />}
          />
        </CardContent>
      </Card>
    </div>
  );
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

function csvValues(value: FormDataEntryValue | null) {
  return String(value ?? '')
    .split(',')
    .map((item) => item.trim())
    .filter(Boolean);
}

async function sha256HexBrowser(input: string) {
  const buffer = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(input));
  return [...new Uint8Array(buffer)].map((byte) => byte.toString(16).padStart(2, '0')).join('');
}

export function HighScalePage({
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
  const [artifactDrafts, setArtifactDrafts] = useState<Record<string, { filename: string; content_sha256: string; custody_id: string }>>({});
  const [selectedRequestId, setSelectedRequestId] = useState(() => getString(data.highScale[0] ?? {}, ['id'], ''));
  const firstTargetGroupEnvironment = getString(data.targetGroups[0] ?? {}, ['environment_id'], '');
  const activeRequest = data.highScale.find((item) => getString(item, ['id'], '') === selectedRequestId) ?? data.highScale[0] ?? null;
  const artifacts = Array.isArray(activeRequest?.artifacts) ? activeRequest.artifacts as DataItem[] : [];
  const packStatus = getNestedItem(activeRequest, ['authorization_pack_status']);
  const packRequirements = getNestedArray(packStatus, ['requirements']);
  const missingRequirementCount = packRequirements.filter((item) => getString(item, ['status'], '') !== 'accepted').length;
  const lifecycleTrail = buildLifecycleTimeline(activeRequest);
  const requiredArtifactTypes = authorizationArtifactTypesForRequest(activeRequest);
  const providerChecklist = Array.isArray(activeRequest?.provider_approval_checklist)
    ? activeRequest.provider_approval_checklist as DataItem[]
    : [];
  const requestColumns: TableColumn<DataItem>[] = [
    { key: 'objective', label: 'Request', render: (item) => getString(item, ['objective', 'reason', 'id']) },
    { key: 'state', label: 'State', render: (item) => <Badge tone={getString(item, ['state']) === 'submitted' ? 'warn' : 'info'}>{getString(item, ['state'])}</Badge> },
    { key: 'target', label: 'Target group', render: (item) => getString(item, ['target_group_id']) },
    { key: 'pack', label: 'Pack', render: (item) => <Badge tone={getNestedString(item, ['authorization_pack_status', 'overall']) === 'accepted' ? 'success' : 'warn'}>{getNestedString(item, ['authorization_pack_status', 'overall'], 'missing')}</Badge> },
    { key: 'window', label: 'Window', render: (item) => formatDate(getNestedString(item, ['requested_window', 'window_start'], '')) },
    {
      key: 'actions',
      label: 'Actions',
      render: (item) => {
        const id = getString(item, ['id'], '');
        return <Button size="sm" variant="secondary" onClick={() => setSelectedRequestId(id)}>Select</Button>;
      }
    }
  ];
  const artifactColumns: TableColumn<DataItem>[] = [
    { key: 'type', label: 'Type', render: (item) => authorizationArtifactTitle(getString(item, ['type'])) },
    {
      key: 'review',
      label: 'Review state',
      render: (item) => {
        const type = getString(item, ['type']);
        const requirement = packRequirementForType(packStatus, type);
        const tone = getString(item, ['status']) === 'accepted' ? 'success' : getString(item, ['status']) === 'rejected' ? 'danger' : 'warn';
        return (
          <div className="stack-tight">
            <Badge tone={tone}>{getString(item, ['status'], 'pending_review')}</Badge>
            <p className="muted small">{explainArtifactReviewStatus(type, requirement, item)}</p>
          </div>
        );
      }
    },
    { key: 'filename', label: 'Filename', render: (item) => getString(item, ['filename_redacted', 'filename'], 'metadata reference') },
    { key: 'digest', label: 'content_sha256', render: (item) => getString(item, ['content_sha256'], 'recorded').slice(0, 16) },
    { key: 'custody', label: 'custody_id', render: (item) => getString(item, ['custody_id'], 'assigned on upload') },
    { key: 'created', label: 'Created', render: (item) => formatDate(item.created_at) }
  ];

  useEffect(() => {
    if (data.highScale.length === 0) {
      if (selectedRequestId) setSelectedRequestId('');
      return;
    }
    const selectedStillExists = data.highScale.some((item) => getString(item, ['id'], '') === selectedRequestId);
    if (!selectedStillExists) setSelectedRequestId(getString(data.highScale[0] ?? {}, ['id'], ''));
  }, [data.highScale, selectedRequestId]);

  async function runHighScaleAction<T>(label: string, action: () => Promise<T>, success: string) {
    setBusy(label);
    setError('');
    setMessage('');
    try {
      const result = await action();
      setMessage(success);
      await onRefresh();
      return result;
    } catch (err) {
      const payload = (err as Error & { payload?: unknown }).payload as { error?: string; message?: string; missing?: string[] } | undefined;
      const missing = Array.isArray(payload?.missing) ? ` Missing: ${payload.missing.join(', ')}.` : '';
      setError(`${payload?.message ?? payload?.error ?? (err instanceof Error ? err.message : 'High-scale action failed.')}${missing}`);
      return null;
    } finally {
      setBusy('');
    }
  }

  async function handleCreateRequest(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const formElement = event.currentTarget;
    const form = new FormData(formElement);
    const duration = Number(form.get('max_duration_minutes') ?? 45);
    const maxErrorRate = Number(form.get('max_error_rate_pct') ?? 5);
    const body = {
      target_group_id: String(form.get('target_group_id') ?? '').trim(),
      objective: String(form.get('objective') ?? '').trim(),
      environment: String(form.get('environment') ?? 'staging').trim(),
      business_criticality: String(form.get('business_criticality') ?? 'high').trim(),
      requested_scenario_families: csvValues(form.get('requested_scenario_families')),
      requested_limits: {
        max_rate: String(form.get('max_rate') ?? '').trim(),
        max_duration_minutes: Number.isFinite(duration) && duration > 0 ? duration : 45
      },
      stop_criteria: {
        abort_on_customer_signal: true,
        max_error_rate_pct: Number.isFinite(maxErrorRate) && maxErrorRate > 0 ? maxErrorRate : 5
      },
      abort_criteria: {
        threshold: String(form.get('abort_threshold') ?? 'error_rate_above_5pct').trim(),
        auto_stop: true
      },
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
      scope_confirmation: form.get('scope_confirmation') === 'on'
    };
    const created = await runHighScaleAction('create-high-scale', () => requestJson(config, session, '/v1/high-scale-requests', {
      method: 'POST',
      body
    }), 'High-scale request submitted for SOC review.');
    if (created && typeof created === 'object') {
      setSelectedRequestId(getString(created as DataItem, ['id'], selectedRequestId));
      formElement.reset();
    }
  }

  function updateArtifactDraft(type: string, field: 'filename' | 'content_sha256' | 'custody_id', value: string) {
    setArtifactDrafts((current) => ({
      ...current,
      [type]: {
        filename: current[type]?.filename ?? '',
        content_sha256: current[type]?.content_sha256 ?? '',
        custody_id: current[type]?.custody_id ?? '',
        [field]: value
      }
    }));
  }

  async function handleUploadArtifactType(type: string) {
    if (!activeRequest) return;
    const requestId = getString(activeRequest, ['id'], '');
    const draft = artifactDrafts[type] ?? { filename: '', content_sha256: '', custody_id: '' };
    const filename = draft.filename.trim();
    if (!filename) {
      setError(`Filename is required for ${authorizationArtifactTitle(type)}.`);
      return;
    }
    const digest = draft.content_sha256.trim()
      || await sha256HexBrowser(`authorization-artifact:${requestId}:${type}:${filename}`);
    const body = buildMetadataArtifactUploadBody(activeRequest, type, {
      filename,
      content_sha256: digest,
      custody_id: draft.custody_id.trim() || undefined
    });
    const uploaded = await runHighScaleAction(`upload-artifact-${type}`, () => requestJson(config, session, `/v1/high-scale-requests/${requestId}/artifacts`, {
      method: 'POST',
      body
    }), `${authorizationArtifactTitle(type)} metadata uploaded.`);
    if (uploaded) {
      setArtifactDrafts((current) => ({
        ...current,
        [type]: { filename: '', content_sha256: '', custody_id: '' }
      }));
    }
  }

  return (
    <div className="content">
      <PageHeader route="high-scale" eyebrow="SOC-gated validation" />
      {data.highScale.length === 0 ? (
        <EmptyState
          icon={ShieldCheck}
          title="No high-scale requests yet."
          body="Submit a governed request with scope confirmation. AstraNull SOC reviews authorization metadata before any execution is scheduled."
        />
      ) : null}
      <div className="metric-grid three">
        <MetricCard label="Requests" value={data.highScale.length} sub="Customer-created, SOC-controlled" icon={ShieldCheck} tone="info" />
        <MetricCard label="Selected pack" value={getString(packStatus ?? {}, ['overall'], activeRequest ? 'missing' : 'None')} sub={`${missingRequirementCount} requirements not accepted`} icon={FileCheck2} tone={getString(packStatus ?? {}, ['overall']) === 'accepted' ? 'success' : 'warn'} />
        <MetricCard label="Artifacts" value={artifacts.length} sub="Metadata-only custody references" icon={FileText} tone="muted" />
      </div>
      {(message || error) && (
        <div className={error ? 'form-banner error' : 'form-banner'}>
          {error || message}
        </div>
      )}
      <div className="split">
        <Card>
          <CardHeader>
            <CardTitle>Request governed validation</CardTitle>
            <CardDescription>Submit authorization metadata for SOC review. Customers cannot approve, schedule, start, stop, or close high-scale execution.</CardDescription>
          </CardHeader>
          <CardContent>
            <form className="product-form" onSubmit={handleCreateRequest}>
              <label>
                <span>Target group</span>
                <select name="target_group_id" required defaultValue={getString(data.targetGroups[0] ?? {}, ['id'], '')}>
                  <option value="">Select declared scope</option>
                  {data.targetGroups.map((group) => (
                    <option key={getString(group, ['id'])} value={getString(group, ['id'])}>{getString(group, ['name', 'id'])}</option>
                  ))}
                </select>
              </label>
              <label>
                <span>Environment</span>
                <input name="environment" defaultValue={firstTargetGroupEnvironment} placeholder="staging" required />
              </label>
              <label className="full">
                <span>Objective</span>
                <textarea name="objective" rows={3} placeholder="Describe the governed readiness validation objective." required />
              </label>
              <label>
                <span>Business criticality</span>
                <select name="business_criticality" defaultValue="high">
                  <option value="medium">Medium</option>
                  <option value="high">High</option>
                  <option value="critical">Critical</option>
                </select>
              </label>
              <label>
                <span>Scenario families</span>
                <input name="requested_scenario_families" defaultValue="volumetric_metadata" placeholder="volumetric_metadata" required />
              </label>
              <label>
                <span>Max rate</span>
                <input name="max_rate" defaultValue="500_rps_metadata" placeholder="500_rps_metadata" required />
              </label>
              <label>
                <span>Max duration</span>
                <input name="max_duration_minutes" type="number" min="1" max="240" defaultValue="45" />
              </label>
              <label>
                <span>Window start</span>
                <input name="window_start" type="datetime-local" defaultValue={datetimeLocalValue(24)} required />
              </label>
              <label>
                <span>Window end</span>
                <input name="window_end" type="datetime-local" defaultValue={datetimeLocalValue(48)} required />
              </label>
              <label>
                <span>Provider</span>
                <input name="provider_name" defaultValue="Cloudflare" placeholder="Provider name" required />
              </label>
              <label>
                <span>Stop threshold</span>
                <input name="max_error_rate_pct" type="number" min="1" max="100" defaultValue="5" />
              </label>
              <label>
                <span>Abort criteria</span>
                <input name="abort_threshold" defaultValue="error_rate_above_5pct" placeholder="error_rate_above_5pct" required />
              </label>
              <label>
                <span>Emergency contact</span>
                <input name="contact_name" defaultValue="Primary on-call" placeholder="Primary on-call" required />
              </label>
              <label>
                <span>Contact path</span>
                <input name="contact" defaultValue="ops@example.invalid" placeholder="ops@example.com or bridge path" required />
              </label>
              <label>
                <span>Timezone</span>
                <input name="timezone" defaultValue="UTC" />
              </label>
              <label className="check-row">
                <input name="requires_provider_approval" type="checkbox" defaultChecked />
                <span>Provider approval is required.</span>
              </label>
              <label className="check-row full">
                <input name="scope_confirmation" type="checkbox" defaultChecked required />
                <span>Declared scope and authorization metadata are accurate.</span>
              </label>
              <div className="form-actions full">
                <Button type="submit" disabled={busy !== '' || data.targetGroups.length === 0}>{busy === 'create-high-scale' ? 'Submitting...' : 'Submit high-scale request'}</Button>
              </div>
            </form>
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>Authorization pack uploads</CardTitle>
            <CardDescription>Metadata-only references per required artifact type (`type`, `filename`, `content_sha256`, optional `custody_id`). Raw documents are not uploaded here.</CardDescription>
          </CardHeader>
          <CardContent>
            {data.highScale.length === 0 ? (
              <EmptyState icon={FileCheck2} title="No high-scale request selected." body="Submit a request before uploading authorization artifacts." />
            ) : (
              <div className="stack">
                <label className="full">
                  <span>Request</span>
                  <select value={selectedRequestId || getString(activeRequest ?? {}, ['id'], '')} onChange={(event) => setSelectedRequestId(event.target.value)} required>
                    {data.highScale.map((request) => (
                      <option key={getString(request, ['id'])} value={getString(request, ['id'])}>{getString(request, ['objective', 'id'])}</option>
                    ))}
                  </select>
                </label>
                <div className="artifact-upload-grid">
                  {requiredArtifactTypes.map((type) => {
                    const requirement = packRequirementForType(packStatus, type);
                    const artifact = bestArtifactForType(artifacts, type);
                    const draft = artifactDrafts[type] ?? { filename: '', content_sha256: '', custody_id: '' };
                    const requirementStatus = getString(requirement ?? {}, ['status'], 'missing');
                    const reviewTone = requirementStatus === 'accepted' ? 'success' : requirementStatus === 'rejected' ? 'danger' : 'warn';
                    return (
                      <div key={type} className="artifact-upload-card">
                        <div className="artifact-upload-card__header">
                          <div>
                            <strong>{authorizationArtifactTitle(type)}</strong>
                            <p className="muted small">{authorizationArtifactPurpose(type)}</p>
                          </div>
                          <Badge tone={reviewTone}>{requirementStatus}</Badge>
                        </div>
                        <p className="muted small">{explainArtifactReviewStatus(type, requirement, artifact)}</p>
                        {artifact ? (
                          <div className="artifact-upload-card__meta muted small">
                            <div><strong>custody_id</strong> {getString(artifact, ['custody_id'], 'pending')}</div>
                            <div><strong>content_sha256</strong> {getString(artifact, ['content_sha256'], 'recorded').slice(0, 24)}</div>
                            <div><strong>filename</strong> {getString(artifact, ['filename_redacted', 'filename'], 'metadata reference')}</div>
                          </div>
                        ) : null}
                        <div className="product-form compact">
                          <label>
                            <span>Artifact type</span>
                            <input value={type} readOnly aria-readonly="true" />
                          </label>
                          <label>
                            <span>Filename</span>
                            <input
                              value={draft.filename}
                              placeholder={`${type}.pdf.metadata`}
                              onChange={(event) => updateArtifactDraft(type, 'filename', event.target.value)}
                            />
                          </label>
                          <label>
                            <span>Content SHA-256</span>
                            <input
                              value={draft.content_sha256}
                              placeholder="Auto-computed from metadata when blank"
                              onChange={(event) => updateArtifactDraft(type, 'content_sha256', event.target.value)}
                            />
                          </label>
                          <label>
                            <span>Custody ID</span>
                            <input
                              value={draft.custody_id}
                              placeholder={artifact ? getString(artifact, ['custody_id'], 'assigned on upload') : 'Optional customer custody reference'}
                              onChange={(event) => updateArtifactDraft(type, 'custody_id', event.target.value)}
                            />
                          </label>
                          <div className="form-actions">
                            <Button
                              type="button"
                              size="sm"
                              disabled={busy !== ''}
                              onClick={() => void handleUploadArtifactType(type)}
                            >
                              {busy === `upload-artifact-${type}` ? 'Uploading...' : 'Upload metadata'}
                            </Button>
                          </div>
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>
            )}
          </CardContent>
        </Card>
      </div>
      <Card>
        <CardHeader>
          <div>
            <CardTitle>High-scale requests</CardTitle>
            <CardDescription>Rows are loaded from `/v1/high-scale-requests`; execution stays SOC-only.</CardDescription>
          </div>
          <Badge tone="info">{data.highScale.length} requests</Badge>
        </CardHeader>
        <CardContent>
          <DataTable
            columns={requestColumns}
            items={data.highScale}
            empty={<EmptyState icon={ShieldCheck} title="No governed requests." body="Submit a high-scale request after declaring target scope and authorization metadata." />}
          />
        </CardContent>
      </Card>
      <div className="split">
        <Card>
          <CardHeader>
            <CardTitle>Authorization pack status</CardTitle>
            <CardDescription>Computed by the backend from intake fields, required artifacts, and provider checklist state.</CardDescription>
          </CardHeader>
          <CardContent className="queue-list">
            {!activeRequest ? (
              <EmptyState icon={FileCheck2} title="No request selected." body="Select or submit a request to inspect authorization requirements." />
            ) : packRequirements.length === 0 ? (
              <EmptyState icon={FileCheck2} title="No requirements returned." body="The backend did not return authorization pack requirement details yet." />
            ) : packRequirements.map((requirement) => {
              const type = getString(requirement, ['type']);
              const artifact = bestArtifactForType(artifacts, type);
              const status = getString(requirement, ['status']);
              return (
                <div key={type} className="stack-tight">
                  <div>
                    <Badge tone={status === 'accepted' ? 'success' : status === 'rejected' ? 'danger' : 'warn'}>{status}</Badge>
                    <span>{authorizationArtifactTitle(type)}</span>
                  </div>
                  <p className="muted small">{explainArtifactReviewStatus(type, requirement, artifact)}</p>
                </div>
              );
            })}
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>Selected request artifacts</CardTitle>
            <CardDescription>Artifacts are metadata references only; raw documents and payloads are rejected by the API.</CardDescription>
          </CardHeader>
          <CardContent>
            <DataTable
              columns={artifactColumns}
              items={artifacts}
              empty={<EmptyState icon={FileText} title="No artifacts attached." body="Upload authorization metadata references for SOC review." />}
            />
          </CardContent>
        </Card>
      </div>
      <div className="split">
        <Card>
          <CardHeader>
            <CardTitle>Lifecycle timeline</CardTitle>
            <CardDescription>
              {activeRequest
                ? `Recorded transitions from audit_trail only. Current request state: ${getString(activeRequest, ['state'])}.`
                : 'Customer-visible state transitions from audit_trail on the selected request.'}
            </CardDescription>
          </CardHeader>
          <CardContent>
            {!activeRequest ? (
              <EmptyState icon={Clock3} title="No request selected." body="Select a governed request to inspect lifecycle history." />
            ) : lifecycleTrail.length === 0 ? (
              <EmptyState icon={Clock3} title="No lifecycle events yet." body="State transitions appear after SOC review, scheduling, execution, or closure actions are recorded." />
            ) : (
              <div className="timeline-list">
                {lifecycleTrail.map((event, index) => (
                  <div key={`${event.action}-${event.at}-${index}`}>
                    <span>{index + 1}</span>
                    <div>
                      <strong>{event.action}</strong>
                      <p>{formatDate(event.at)} · {event.by}</p>
                      {event.metadata && Object.keys(event.metadata).length > 0 ? (
                        <p className="muted small">Recorded metadata: {Object.keys(event.metadata).join(', ')}</p>
                      ) : null}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>Provider approval checklist</CardTitle>
            <CardDescription>Provider-specific approval metadata required before SOC can schedule governed execution.</CardDescription>
          </CardHeader>
          <CardContent className="queue-list">
            {!activeRequest ? (
              <EmptyState icon={ShieldCheck} title="No request selected." body="Provider checklist items are created from intake provider context and approval artifacts." />
            ) : providerChecklist.length === 0 ? (
              <EmptyState icon={ShieldCheck} title="No provider checklist items." body="Declare provider context on intake or upload a provider_approval artifact to populate checklist state." />
            ) : providerChecklist.map((item) => (
              <div key={getString(item, ['provider_key', 'provider_name'], '')}>
                <Badge tone={getString(item, ['status'], '') === 'approved' ? 'success' : 'warn'}>{getString(item, ['status'], 'pending')}</Badge>
                <span>{getString(item, ['provider_name'], 'provider')} · {getString(item, ['approval_reference'], 'no reference')}</span>
              </div>
            ))}
          </CardContent>
        </Card>
      </div>
      <Card>
        <CardHeader>
          <CardTitle>SOC handoff (read-only)</CardTitle>
          <CardDescription>Customers submit requests and authorization metadata here. Approval, scheduling, execution, stop, and close remain on the SOC console — this page does not call `/internal/soc/*` routes.</CardDescription>
        </CardHeader>
        <CardContent className="row-actions">
          <AnchorButton href="#soc" variant="secondary" size="sm">Open SOC console</AnchorButton>
          <AnchorButton href="#support" variant="ghost" size="sm">Open support readiness</AnchorButton>
        </CardContent>
      </Card>

    </div>
  );
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

const REPORT_KIND_OPTIONS = [
  { value: 'executive', label: 'Executive' },
  { value: 'board', label: 'Board' },
  { value: 'technical', label: 'Technical' },
  { value: 'soc', label: 'SOC' },
  { value: 'audit', label: 'Audit' },
  { value: 'soc2', label: 'SOC 2' },
  { value: 'iso27001', label: 'ISO 27001' },
  { value: 'dora', label: 'DORA' },
  { value: 'nis2', label: 'NIS2' },
  { value: 'internal_audit', label: 'Internal audit' }
];

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
  const [preview, setPreview] = useState<ReportExportPreview | null>(null);
  const reports = data.reports;
  const latestReport = reports[0] ?? null;
  const reportExports = data.audit.filter((entry) => getString(entry, ['action'], '') === 'report.exported').length;
  const reportColumns: TableColumn<DataItem>[] = [
    {
      key: 'title',
      label: 'Report',
      render: (item) => {
        const id = getString(item, ['id'], '');
        const title = getString(item, ['title', 'id']);
        return id
          ? <AnchorButton size="sm" variant="ghost" href={buildDetailHref('report-detail', id)}>{title}</AnchorButton>
          : title;
      }
    },
    { key: 'kind', label: 'Kind', render: (item) => <Badge tone="info">{getString(item, ['kind'])}</Badge> },
    { key: 'readiness', label: 'Readiness', render: (item) => `${getNestedNumber(item, ['summary', 'readiness_score'], 0)}%` },
    { key: 'findings', label: 'Open findings', render: (item) => getNestedNumber(item, ['summary', 'open_findings'], 0) },
    { key: 'created', label: 'Created', render: (item) => formatDate(item.created_at) },
    {
      key: 'actions',
      label: 'Actions',
      render: (item) => {
        const id = getString(item, ['id'], '');
        return (
          <div className="row-actions">
            <AnchorButton size="sm" variant="secondary" href={buildDetailHref('report-detail', id)}>Detail</AnchorButton>
            <Button size="sm" variant="secondary" disabled={busy !== ''} onClick={() => void exportReport(id, 'json')}>JSON</Button>
            <Button size="sm" variant="secondary" disabled={busy !== ''} onClick={() => void exportReport(id, 'markdown')}>MD</Button>
            <Button size="sm" variant="secondary" disabled={busy !== ''} onClick={() => void exportReport(id, 'html')}>HTML</Button>
          </div>
        );
      }
    }
  ];

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

  async function handleCreateReport(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const formElement = event.currentTarget;
    const form = new FormData(formElement);
    const title = String(form.get('title') ?? '').trim() || 'AstraNull Readiness Summary';
    const kind = String(form.get('kind') ?? 'technical');
    const created = await runReportAction('create-report', () => requestJson(config, session, '/v1/reports', {
      method: 'POST',
      body: { title, kind }
    }), 'Report generated from current workspace data.');
    if (created && typeof created === 'object') {
      formElement.reset();
      await onRefresh();
      const id = getString(created as DataItem, ['id'], '');
      if (id) await exportReport(id, 'json');
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
        setPreview({
          reportId,
          format,
          title: getNestedString(payload, ['title'], getString(reports.find((report) => getString(report, ['id'], '') === reportId) ?? {}, ['title'], reportId)),
          contentSha256: getString(custody ?? {}, ['content_sha256'], ''),
          artifactId: getString(custody ?? {}, ['artifact_id'], ''),
          schemaVersion: getString(custody ?? {}, ['schema_version'], ''),
          verification
        });
        await onRefresh();
        return exported;
      }
      const textPayload = await response.text();
      setPreview({
        reportId,
        format,
        title: getString(reports.find((report) => getString(report, ['id'], '') === reportId) ?? {}, ['title'], reportId),
        textPreview: textPayload.slice(0, 900)
      });
      await onRefresh();
      return textPayload;
    }, `Report exported as ${format}.`);
  }

  return (
    <div className="content">
      <PageHeader route="reports" />
      <div className="metric-grid three">
        <MetricCard label="Reports" value={reports.length} sub="Generated from tenant evidence" icon={FileText} tone="info" />
        <MetricCard label="Exports" value={reportExports} sub="Audit records with custody digests" icon={FileCheck2} tone="success" />
        <MetricCard label="Latest" value={latestReport ? getString(latestReport, ['kind']) : 'None'} sub={latestReport ? formatDate(latestReport.created_at) : 'Generate a report first'} icon={Clock3} tone={latestReport ? 'muted' : 'warn'} />
      </div>
      {(message || error) && (
        <div className={error ? 'form-banner error' : 'form-banner'}>
          {error || message}
        </div>
      )}
      <div className="split">
        <Card>
          <CardHeader>
            <CardTitle>Generate report</CardTitle>
            <CardDescription>Create a tenant-scoped report from current readiness, run, finding, and compliance mapping data.</CardDescription>
          </CardHeader>
          <CardContent>
            <form className="product-form" onSubmit={handleCreateReport}>
              <label className="full">
                <span>Title</span>
                <input name="title" placeholder="Q3 readiness evidence pack" />
              </label>
              <label>
                <span>Report kind</span>
                <select name="kind" defaultValue="technical">
                  {REPORT_KIND_OPTIONS.map((option) => (
                    <option key={option.value} value={option.value}>{option.label}</option>
                  ))}
                </select>
              </label>
              <div className="form-actions full">
                <Button type="submit" disabled={busy !== ''}>{busy === 'create-report' ? 'Generating...' : 'Generate report'}</Button>
              </div>
            </form>
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>Export custody</CardTitle>
            <CardDescription>JSON exports are verified through `/v1/custody/verify`; text exports render a safe preview.</CardDescription>
          </CardHeader>
          <CardContent className={preview ? 'kv-list' : ''}>
            {!preview ? (
              <EmptyState icon={FileCheck2} title="No export selected." body="Generate or export a report to inspect custody metadata." />
            ) : preview.contentSha256 ? (
              <>
                <div><span>Report</span><strong>{preview.title}</strong></div>
                <div><span>Artifact</span><strong>{preview.artifactId}</strong></div>
                <div><span>content_sha256</span><strong>{preview.contentSha256}</strong></div>
                <div><span>Schema</span><strong>{preview.schemaVersion}</strong></div>
                <div><span>Verification</span><strong>{getString(preview.verification ?? {}, ['ok'], 'verified')}</strong></div>
              </>
            ) : (
              <pre className="codeblock">{preview.textPreview}</pre>
            )}
          </CardContent>
        </Card>
      </div>
      <Card>
        <CardHeader>
          <div>
            <CardTitle>Generated reports</CardTitle>
            <CardDescription>Rows come from `/v1/reports`; exports call the backend and append custody audit metadata.</CardDescription>
          </div>
          <Badge tone="info">{reports.length} records</Badge>
        </CardHeader>
        <CardContent className="stack-tight">
          <DataTable
            columns={reportColumns}
            items={reports}
            empty={<EmptyState icon={FileText} title="No reports generated." body="Generate a report after validation activity to create a custody-ready evidence artifact." />}
          />
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

function expiresAtFromForm(value: string) {
  const now = Date.now();
  if (value === '15m') return new Date(now + 15 * 60 * 1000).toISOString();
  if (value === '1h') return new Date(now + 60 * 60 * 1000).toISOString();
  if (value === '24h') return new Date(now + 24 * 60 * 60 * 1000).toISOString();
  if (value === '30d') return new Date(now + 30 * 24 * 60 * 60 * 1000).toISOString();
  return null;
}

type SettingsTab = 'organization' | 'users' | 'api-keys' | 'sso' | 'retention' | 'secrets' | 'audit';

const SETTINGS_TAB_OPTIONS: { id: SettingsTab; label: string }[] = [
  { id: 'organization', label: 'Organization' },
  { id: 'users', label: 'Users & roles' },
  { id: 'api-keys', label: 'API keys' },
  { id: 'sso', label: 'SSO' },
  { id: 'retention', label: 'Data retention' },
  { id: 'secrets', label: 'Secret vault' },
  { id: 'audit', label: 'Audit log' }
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
  const [tab, setTab] = useState<SettingsTab>('organization');
  const [busy, setBusy] = useState('');
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');
  const [oneTimeSecret, setOneTimeSecret] = useState<{ label: string; value: string } | null>(null);
  const [rotateSecretId, setRotateSecretId] = useState('');
  const tenant = data.tenant;
  const privacy = getNestedItem(tenant, ['privacy_settings']) ?? {};
  const evidenceRetention = getNestedItem(privacy, ['evidence_retention']) ?? {};
  const metadataRetentionDays = getNumber(privacy, ['metadata_retention_days'], 90);
  const oidcPosture = readOidcPosture(config);
  const routeAccessContext = {
    principal: session.principal,
    staffRole: session.staff_role,
  };
  const role = session.role ?? 'admin';
  const canReadAudit = canAccessRoute(role, 'audit', routeAccessContext);
  const canReadNotifications = canAccessRoute(role, 'notifications', routeAccessContext);
  const canReadReleaseEvidence = canAccessRoute(role, 'release-evidence', routeAccessContext);
  const settingsTabOptions = SETTINGS_TAB_OPTIONS.filter((option) => (
    option.id !== 'audit' || canReadAudit
  ));
  const tokenColumns: TableColumn<DataItem>[] = [
    { key: 'name', label: 'Token', render: (item) => getString(item, ['name', 'id']) },
    { key: 'environment', label: 'Environment', render: (item) => getString(item, ['environment_id']) },
    { key: 'usage', label: 'Usage', render: (item) => `${getNumber(item, ['registrations_used'])}/${getNumber(item, ['max_registrations'], 1)}` },
    { key: 'expires', label: 'Expires', render: (item) => formatDate(item.expires_at) },
    { key: 'state', label: 'State', render: (item) => <Badge tone={item.revoked_at ? 'muted' : 'success'}>{item.revoked_at ? 'revoked' : 'active'}</Badge> },
    {
      key: 'actions',
      label: 'Actions',
      render: (item) => {
        const id = getString(item, ['id'], '');
        return <Button size="sm" variant="danger" disabled={busy !== '' || Boolean(item.revoked_at)} onClick={() => void revokeBootstrapToken(id)}>Revoke</Button>;
      }
    }
  ];
  const serviceAccountColumns: TableColumn<DataItem>[] = [
    { key: 'name', label: 'Account', render: (item) => getString(item, ['name', 'id']) },
    { key: 'role', label: 'Role', render: (item) => <Badge tone="info">{getString(item, ['role'])}</Badge> },
    { key: 'scopes', label: 'Scopes', render: (item) => Array.isArray(item.scopes) ? item.scopes.join(', ') : 'role defaults' },
    { key: 'expires', label: 'Expires', render: (item) => item.expires_at ? formatDate(item.expires_at) : 'No expiry' },
    { key: 'state', label: 'State', render: (item) => <Badge tone={item.revoked_at ? 'muted' : 'success'}>{item.revoked_at ? 'revoked' : 'active'}</Badge> },
    {
      key: 'actions',
      label: 'Actions',
      render: (item) => {
        const id = getString(item, ['id'], '');
        return (
          <div className="row-actions">
            <Button size="sm" variant="secondary" disabled={busy !== '' || Boolean(item.revoked_at)} onClick={() => void rotateServiceAccount(id)}>Rotate</Button>
            <Button size="sm" variant="danger" disabled={busy !== '' || Boolean(item.revoked_at)} onClick={() => void revokeServiceAccount(id)}>Revoke</Button>
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
      const payload = (err as Error & { payload?: unknown }).payload as { error?: string; message?: string } | undefined;
      setError(payload?.message ?? payload?.error ?? (err instanceof Error ? err.message : 'Action failed.'));
      return null;
    } finally {
      setBusy('');
    }
  }

  async function handleCreateBootstrapToken(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const formElement = event.currentTarget;
    const form = new FormData(formElement);
    const name = String(form.get('name') ?? '').trim() || 'Install token';
    const expiry = expiresAtFromForm(String(form.get('expiry') ?? '1h'));
    const maxRegistrations = Number(form.get('max_registrations') ?? 1);
    const targetGroupId = String(form.get('target_group_id') ?? '').trim();
    const result = await runSettingsAction('create-bootstrap-token', () => requestJson(config, session, '/v1/bootstrap-tokens', {
      method: 'POST',
      body: {
        name,
        environment_id: String(form.get('environment_id') ?? 'env_demo'),
        ...(targetGroupId ? { target_group_id: targetGroupId } : {}),
        max_registrations: Number.isFinite(maxRegistrations) && maxRegistrations > 0 ? maxRegistrations : 1,
        ...(expiry ? { expires_at: expiry } : {})
      }
    }), 'Bootstrap token created. Copy the secret now; it is shown once.');
    if (result && typeof result === 'object' && 'secret' in result && typeof (result as { secret?: unknown }).secret === 'string') {
      setOneTimeSecret({ label: 'Bootstrap token secret', value: String((result as { secret: string }).secret) });
      formElement.reset();
    }
  }

  async function handleCreateServiceAccount(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const formElement = event.currentTarget;
    const form = new FormData(formElement);
    const requestedScopes = String(form.get('scopes') ?? '')
      .split(',')
      .map((scope) => scope.trim())
      .filter(Boolean);
    const scopes = requestedScopes.length ? requestedScopes : ['tenant:read'];
    const result = await runSettingsAction('create-service-account', () => requestJson(config, session, '/v1/service-accounts', {
      method: 'POST',
      body: {
        name: String(form.get('name') ?? '').trim() || 'Automation account',
        role: String(form.get('role') ?? 'viewer'),
        scopes,
        ...(expiresAtFromForm(String(form.get('expiry') ?? '')) ? { expires_at: expiresAtFromForm(String(form.get('expiry') ?? '')) } : {})
      }
    }), 'Service account created. Copy the API secret now; it is shown once.');
    if (result && typeof result === 'object' && 'secret' in result && typeof (result as { secret?: unknown }).secret === 'string') {
      setOneTimeSecret({ label: 'Service API secret', value: String((result as { secret: string }).secret) });
      formElement.reset();
    }
  }

  async function revokeBootstrapToken(id: string) {
    if (!id) return;
    await runSettingsAction(`revoke-bootstrap-${id}`, () => requestJson(config, session, `/v1/bootstrap-tokens/${id}/revoke`, { method: 'POST' }), 'Bootstrap token revoked.');
  }

  async function revokeServiceAccount(id: string) {
    if (!id) return;
    await runSettingsAction(`revoke-service-${id}`, () => requestJson(config, session, `/v1/service-accounts/${id}/revoke`, { method: 'POST' }), 'Service account revoked.');
  }

  async function rotateServiceAccount(id: string) {
    if (!id) return;
    const result = await runSettingsAction(`rotate-service-${id}`, () => requestJson(config, session, `/v1/service-accounts/${id}/rotate`, { method: 'POST' }), 'Service account rotated. Copy the new API secret now; it is shown once.');
    if (result && typeof result === 'object' && 'secret' in result && typeof (result as { secret?: unknown }).secret === 'string') {
      setOneTimeSecret({ label: 'Rotated service API secret', value: String((result as { secret: string }).secret) });
    }
  }

  async function handleSaveOrganization(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
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

  async function handleSaveRetention(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const metadataDays = Number(form.get('metadata_retention_days') ?? 90);
    const reportDays = Number(form.get('report_days') ?? 365);
    const auditLogDays = Number(form.get('audit_log_days') ?? 2555);
    const highScaleArtifactDays = Number(form.get('high_scale_artifact_days') ?? 2555);
    const legalHold = form.get('legal_hold') === 'on';
    await runSettingsAction('save-retention', () => requestJson(config, session, '/v1/tenants/current', {
      method: 'PATCH',
      body: {
        privacy_settings: {
          metadata_retention_days: metadataDays,
          evidence_retention: {
            report_days: reportDays,
            audit_log_days: auditLogDays,
            high_scale_artifact_days: highScaleArtifactDays,
            legal_hold: legalHold
          }
        }
      }
    }), 'Retention policy saved. Metadata purge runs immediately when retention days change.');
  }

  async function handleCreateVaultSecret(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const formElement = event.currentTarget;
    const form = new FormData(formElement);
    const purpose = String(form.get('purpose') ?? '').trim();
    const name = String(form.get('name') ?? '').trim();
    const plaintext = String(form.get('plaintext') ?? '').trim();
    if (!purpose || !name || !plaintext) {
      setError('Purpose, name, and credential value are required.');
      return;
    }
    await runSettingsAction('create-vault-secret', () => requestJson(config, session, '/v1/secrets', {
      method: 'POST',
      body: {
        purpose,
        name,
        plaintext,
        metadata: { source: 'settings_vault' }
      }
    }), 'Integration secret stored. Plaintext is never returned by list APIs.');
    formElement.reset();
  }

  async function handleRotateVaultSecret(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const formElement = event.currentTarget;
    const form = new FormData(formElement);
    const id = String(form.get('secret_id') ?? rotateSecretId).trim();
    const plaintext = String(form.get('plaintext') ?? '').trim();
    if (!id || !plaintext) {
      setError('Select a secret and provide the replacement credential value.');
      return;
    }
    await runSettingsAction(`rotate-vault-${id}`, () => requestJson(config, session, `/v1/secrets/${id}/rotate`, {
      method: 'POST',
      body: { plaintext }
    }), 'Secret rotated. Prior credential stops working for authorized internal workflows.');
    formElement.reset();
    setRotateSecretId('');
  }

  const secretColumns: TableColumn<DataItem>[] = [
    { key: 'name', label: 'Name', render: (item) => getString(item, ['name', 'id']) },
    { key: 'purpose', label: 'Purpose', render: (item) => <Badge tone="info">{getString(item, ['purpose'])}</Badge> },
    { key: 'rotation', label: 'Rotation', render: (item) => getNumber(item, ['rotation']) },
    { key: 'updated', label: 'Updated', render: (item) => formatDate(item.updated_at ?? item.created_at) },
    {
      key: 'actions',
      label: 'Actions',
      render: (item) => {
        const id = getString(item, ['id'], '');
        return (
          <Button
            size="sm"
            variant="secondary"
            disabled={busy !== ''}
            onClick={() => {
              setRotateSecretId(id);
              setTab('secrets');
            }}
          >
            Rotate
          </Button>
        );
      }
    }
  ];

  const auditPreviewColumns: TableColumn<DataItem>[] = [
    { key: 'action', label: 'Action', render: (item) => getString(item, ['action']) },
    { key: 'resource', label: 'Resource', render: (item) => `${getString(item, ['resource_type'], 'record')} · ${getString(item, ['resource_id'])}` },
    { key: 'actor', label: 'Actor', render: (item) => getString(item, ['actor_role', 'actor_user_id']) },
    { key: 'created', label: 'Recorded', render: (item) => formatDate(item.created_at) }
  ];

  return (
    <div className="content">
      <PageHeader route="settings" />
      <Tabs value={tab} options={settingsTabOptions} onChange={setTab} className="tabs-wrap" />
      <div className="metric-grid three">
        <MetricCard label="Organization" value={getString(tenant ?? {}, ['name'], 'Not loaded')} sub={getString(tenant ?? {}, ['id'], data.state?.tenant_id ?? '—')} icon={ShieldCheck} tone="info" />
        <MetricCard label="Secret vault" value={data.secrets.length} sub="Encrypted integration credentials" icon={KeyRound} tone="success" />
        <MetricCard label="Metadata retention" value={`${metadataRetentionDays}d`} sub="Tenant privacy_settings from API" icon={FileCheck2} tone="muted" />
      </div>
      {(message || error) && (
        <div className={error ? 'form-banner error' : 'form-banner'}>
          {error || message}
        </div>
      )}
      {oneTimeSecret && (
        <Card className="secret-card">
          <CardHeader>
            <div>
              <CardTitle>{oneTimeSecret.label}</CardTitle>
              <CardDescription>This value is shown once. It is not returned by list APIs and will not be visible after refresh.</CardDescription>
            </div>
            <div className="row-actions">
              <Button
                variant="secondary"
                size="sm"
                onClick={() => {
                  void navigator.clipboard.writeText(oneTimeSecret.value).then(() => {
                    setMessage('Secret copied to clipboard.');
                    setError('');
                  }).catch(() => {
                    setError('Clipboard copy failed. Select the secret manually.');
                  });
                }}
              >
                Copy secret
              </Button>
              <Button variant="ghost" size="sm" onClick={() => setOneTimeSecret(null)}>Dismiss</Button>
            </div>
          </CardHeader>
          <CardContent>
            <pre className="codeblock">{oneTimeSecret.value}</pre>
          </CardContent>
        </Card>
      )}

      {tab === 'organization' && (
        <div className="split">
          <Card>
            <CardHeader>
              <CardTitle>Organization profile</CardTitle>
              <CardDescription>Tenant name from `GET/PATCH /v1/tenants/current`. Privacy defaults stay metadata-only.</CardDescription>
            </CardHeader>
            <CardContent>
              {tenant ? (
                <form className="product-form" onSubmit={handleSaveOrganization}>
                  <label className="full">
                    <span>Organization name</span>
                    <input name="name" defaultValue={getString(tenant, ['name'])} required />
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
                    <Button type="submit" disabled={busy !== ''}>{busy === 'save-organization' ? 'Saving...' : 'Save organization'}</Button>
                  </div>
                </form>
              ) : (
                <EmptyState icon={ShieldCheck} title="Tenant record unavailable." body="`GET /v1/tenants/current` did not return data for this session." />
              )}
            </CardContent>
          </Card>
          <Card>
            <CardHeader>
              <CardTitle>Workspace inventory</CardTitle>
              <CardDescription>Live counts from tenant APIs; not editable here.</CardDescription>
            </CardHeader>
            <CardContent className="kv-list">
              <div><span>Target groups</span><strong>{data.targetGroups.length}</strong></div>
              <div><span>Agents</span><strong>{data.agents.length}</strong></div>
              <div><span>Evidence records</span><strong>{data.evidence.length}</strong></div>
              <div><span>Environments</span><strong>{new Set(data.targetGroups.map((group) => getString(group, ['environment_id'], 'unassigned'))).size}</strong></div>
            </CardContent>
          </Card>
        </div>
      )}

      {tab === 'users' && (
        <div className="split">
          <Card>
            <CardHeader>
              <CardTitle>Current session</CardTitle>
              <CardDescription>Read-only view of the authenticated principal in this browser session.</CardDescription>
            </CardHeader>
            <CardContent className="kv-list">
              <div><span>User ID</span><strong>{session.user_id ?? '—'}</strong></div>
              <div><span>Role</span><strong>{session.role ?? '—'}</strong></div>
              <div><span>Tenant</span><strong>{session.tenant_id ?? data.state?.tenant_id ?? '—'}</strong></div>
              <div><span>Auth mode</span><strong>{config.authMode}</strong></div>
            </CardContent>
          </Card>
          <Card>
            <CardHeader>
              <CardTitle>User provisioning boundary</CardTitle>
              <CardDescription>Read-only — no customer tenant user API is wired in this release.</CardDescription>
            </CardHeader>
            <CardContent className="settings-list">
              <div><Users size={18} /><span>Invite, disable, and role assignment are provisioned by AstraNull staff through `/internal/admin/*` routes.</span></div>
              <div><ShieldCheck size={18} /><span>Enterprise SSO group-to-role mapping is enforced at the IdP/JWT layer when `auth_mode` is `oidc-jwt`.</span></div>
              <div><FileCheck2 size={18} /><span>Customer admins can review audit entries and API credentials here; user directory management remains staff-operated.</span></div>
            </CardContent>
            <CardContent className="row-actions">
              <AnchorButton href="#admin" variant="secondary" size="sm">Staff admin console</AnchorButton>
              {canReadAudit ? <AnchorButton href="#audit" variant="ghost" size="sm">Tenant audit log</AnchorButton> : null}
            </CardContent>
          </Card>
        </div>
      )}

      {tab === 'api-keys' && (
        <>
          <div className="split">
            <Card>
              <CardHeader>
                <CardTitle>Create bootstrap token</CardTitle>
                <CardDescription>Issue a short-lived one-time install secret for outbound agent registration.</CardDescription>
              </CardHeader>
              <CardContent>
                <form className="product-form" onSubmit={handleCreateBootstrapToken}>
                  <label>
                    <span>Name</span>
                    <input name="name" placeholder="prod-edge-install" />
                  </label>
                  <label>
                    <span>Environment</span>
                    <input name="environment_id" defaultValue="env_demo" />
                  </label>
                  <label>
                    <span>Target group</span>
                    <select name="target_group_id" defaultValue="">
                      <option value="">No default binding</option>
                      {data.targetGroups.map((group) => (
                        <option key={getString(group, ['id'])} value={getString(group, ['id'])}>{getString(group, ['name', 'id'])}</option>
                      ))}
                    </select>
                  </label>
                  <label>
                    <span>Expiry</span>
                    <select name="expiry" defaultValue="1h">
                      <option value="15m">15 minutes</option>
                      <option value="1h">1 hour</option>
                      <option value="24h">24 hours</option>
                    </select>
                  </label>
                  <label>
                    <span>Max registrations</span>
                    <input name="max_registrations" type="number" min="1" max="50" defaultValue="1" />
                  </label>
                  <div className="form-actions full">
                    <Button type="submit" disabled={busy !== ''}>{busy === 'create-bootstrap-token' ? 'Creating...' : 'Create token'}</Button>
                  </div>
                </form>
              </CardContent>
            </Card>
            <Card>
              <CardHeader>
                <CardTitle>Create service account</CardTitle>
                <CardDescription>Create scoped API automation credentials. Secrets are returned once and list views stay redacted.</CardDescription>
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
                    <input name="scopes" defaultValue="tenant:read,evidence:read" />
                  </label>
                  <label>
                    <span>Expiry</span>
                    <select name="expiry" defaultValue="">
                      <option value="">No expiry</option>
                      <option value="24h">24 hours</option>
                      <option value="30d">30 days</option>
                    </select>
                  </label>
                  <div className="form-actions full">
                    <Button type="submit" disabled={busy !== ''}>{busy === 'create-service-account' ? 'Creating...' : 'Create API key'}</Button>
                  </div>
                </form>
              </CardContent>
            </Card>
          </div>
          <Card>
            <CardHeader>
              <div>
                <CardTitle>Bootstrap tokens</CardTitle>
                <CardDescription>Install tokens are redacted after creation and can be revoked immediately.</CardDescription>
              </div>
              <Badge tone="info">{data.bootstrapTokens.length} records</Badge>
            </CardHeader>
            <CardContent>
              <DataTable
                columns={tokenColumns}
                items={data.bootstrapTokens}
                empty={<EmptyState icon={KeyRound} title="No bootstrap tokens." body="Create a short-lived token before installing an outbound-only agent." />}
              />
            </CardContent>
          </Card>
          <Card>
            <CardHeader>
              <div>
                <CardTitle>Service accounts</CardTitle>
                <CardDescription>Automation credentials are scoped, auditable, rotatable, and redacted after creation.</CardDescription>
              </div>
              <Badge tone="success">{data.serviceAccounts.length} records</Badge>
            </CardHeader>
            <CardContent>
              <DataTable
                columns={serviceAccountColumns}
                items={data.serviceAccounts}
                empty={<EmptyState icon={UserCog} title="No service accounts." body="Create an API key only for a clear automation owner and scope." />}
              />
            </CardContent>
          </Card>
        </>
      )}

      {tab === 'sso' && (
        <Card>
          <CardHeader>
            <CardTitle>Enterprise SSO posture</CardTitle>
            <CardDescription>Read-only auth configuration from `/ready` and `/v1/public/site-config`. Secrets and JWKS URLs are never exposed.</CardDescription>
          </CardHeader>
          <CardContent className="kv-list">
            <div><span>Auth mode</span><strong>{oidcPosture.authMode}</strong></div>
            <div><span>OIDC issuer</span><strong>{oidcPosture.issuer ?? 'Not exposed on public readiness endpoints'}</strong></div>
            <div><span>OIDC audience</span><strong>{oidcPosture.audience ?? 'Not exposed on public readiness endpoints'}</strong></div>
            <div><span>Bundled staging login</span><strong>{oidcPosture.bundledStagingLogin ? 'Enabled' : 'Disabled'}</strong></div>
            <div><span>Login URL</span><strong>{config.loginUrl}</strong></div>
          </CardContent>
          <CardContent className="settings-list">
            <div><ShieldCheck size={18} /><span>Production human auth defaults to `oidc-jwt` with JWKS verification; developer validation may use `dev-headers` or bundled staging login.</span></div>
            <div><KeyRound size={18} /><span>Issuer and audience values are configured server-side. Public site-config currently exposes `auth_mode` only unless your deployment extends the payload.</span></div>
          </CardContent>
        </Card>
      )}

      {tab === 'retention' && (
        <Card>
          <CardHeader>
            <CardTitle>Privacy and retention</CardTitle>
            <CardDescription>`PATCH /v1/tenants/current` updates `privacy_settings.metadata_retention_days` and `evidence_retention`. Metadata purge runs immediately when retention changes.</CardDescription>
          </CardHeader>
          <CardContent>
            <form className="product-form" onSubmit={handleSaveRetention}>
              <label>
                <span>Metadata retention (days)</span>
                <input name="metadata_retention_days" type="number" min="1" max="3650" defaultValue={metadataRetentionDays} />
              </label>
              <label>
                <span>Report archive (days)</span>
                <input name="report_days" type="number" min="30" max="3650" defaultValue={getNumber(evidenceRetention, ['report_days'], 365)} />
              </label>
              <label>
                <span>Audit log retention (days)</span>
                <input name="audit_log_days" type="number" min="365" max="3650" defaultValue={getNumber(evidenceRetention, ['audit_log_days'], 2555)} />
              </label>
              <label>
                <span>High-scale artifact retention (days)</span>
                <input name="high_scale_artifact_days" type="number" min="365" max="3650" defaultValue={getNumber(evidenceRetention, ['high_scale_artifact_days'], 2555)} />
              </label>
              <label className="check-row full">
                <input name="legal_hold" type="checkbox" defaultChecked={Boolean(evidenceRetention.legal_hold)} />
                <span>Legal hold — block metadata deletions while legal hold is active (read-only boundary for production legal workflows).</span>
              </label>
              <div className="form-actions full">
                <Button type="submit" disabled={busy !== '' || !tenant}>{busy === 'save-retention' ? 'Saving...' : 'Save retention policy'}</Button>
              </div>
            </form>
          </CardContent>
          <CardContent className="settings-list">
            <div><FileCheck2 size={18} /><span>Metadata retention applies to events, evidence vault, reports, and notification events for the current tenant.</span></div>
            <div><ShieldCheck size={18} /><span>Audit logs, findings, test runs, and authorization artifacts follow separate production gates documented in `docs/api.md`.</span></div>
          </CardContent>
        </Card>
      )}

      {tab === 'secrets' && (
        <>
          <div className="split">
            <Card>
              <CardHeader>
                <CardTitle>Store integration secret</CardTitle>
                <CardDescription>Plaintext is accepted only on create/rotate. List APIs return metadata-only envelopes.</CardDescription>
              </CardHeader>
              <CardContent>
                <form className="product-form" onSubmit={handleCreateVaultSecret}>
                  <label>
                    <span>Purpose</span>
                    <select name="purpose" defaultValue="integration_credential">
                      <option value="integration_credential">Integration credential</option>
                      <option value="waf_connector">WAF connector</option>
                      <option value="webhook_signing">Webhook signing</option>
                      <option value="provider_api">Provider API</option>
                    </select>
                  </label>
                  <label>
                    <span>Name</span>
                    <input name="name" placeholder="cloudflare:edge-readonly" required />
                  </label>
                  <label className="full">
                    <span>Credential value</span>
                    <textarea name="plaintext" rows={4} placeholder="API token or JSON credential" required />
                  </label>
                  <div className="form-actions full">
                    <Button type="submit" disabled={busy !== ''}>{busy === 'create-vault-secret' ? 'Storing...' : 'Store secret'}</Button>
                  </div>
                </form>
              </CardContent>
            </Card>
            <Card>
              <CardHeader>
                <CardTitle>Rotate stored secret</CardTitle>
                <CardDescription>Rotation replaces the encrypted envelope; there is no decrypt endpoint on `/v1`.</CardDescription>
              </CardHeader>
              <CardContent>
                <form className="product-form" onSubmit={handleRotateVaultSecret}>
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
                    <textarea name="plaintext" rows={4} placeholder="New API token or JSON credential" required />
                  </label>
                  <div className="form-actions full">
                    <Button type="submit" disabled={busy !== '' || data.secrets.length === 0}>Rotate secret</Button>
                  </div>
                </form>
              </CardContent>
            </Card>
          </div>
          <Card>
            <CardHeader>
              <div>
                <CardTitle>Secret vault inventory</CardTitle>
                <CardDescription>Tenant-scoped metadata from `GET /v1/secrets` — no plaintext, ciphertext, or auth tags.</CardDescription>
              </div>
              <Badge tone="info">{data.secrets.length} records</Badge>
            </CardHeader>
            <CardContent>
              <DataTable
                columns={secretColumns}
                items={data.secrets}
                empty={<EmptyState icon={KeyRound} title="No secrets stored." body="Store connector or integration credentials here before referencing them from read-only connector workflows." actionLabel="Open Integrations" actionHref="#integrations" />}
              />
            </CardContent>
          </Card>
        </>
      )}

      {tab === 'audit' && (
        <>
          <Card>
            <CardHeader>
              <div>
                <CardTitle>Recent tenant audit entries</CardTitle>
                <CardDescription>Preview from `GET /v1/audit-log`. Full immutable history is on the Audit page.</CardDescription>
              </div>
              <AnchorButton href="#audit" variant="secondary" size="sm">Open audit log</AnchorButton>
            </CardHeader>
            <CardContent>
              <DataTable
                columns={auditPreviewColumns}
                items={data.audit.slice(0, 20)}
                empty={<EmptyState icon={FileCheck2} title="No audit entries yet." body="Security-sensitive actions will appear here after tokens, agents, retention, or validation changes are recorded." />}
              />
            </CardContent>
          </Card>
          <Card>
            <CardHeader>
              <CardTitle>Related governance links</CardTitle>
              <CardDescription>Settings surfaces credentials and retention; audit and release evidence stay in dedicated routes.</CardDescription>
            </CardHeader>
            <CardContent className="row-actions">
              {canReadNotifications ? <AnchorButton href="#notifications" variant="secondary" size="sm">Notification rules</AnchorButton> : null}
              {canReadReleaseEvidence ? <AnchorButton href="#release-evidence" variant="secondary" size="sm">Release evidence</AnchorButton> : null}
              <AnchorButton href="#integrations" variant="ghost" size="sm">Integrations</AnchorButton>
            </CardContent>
          </Card>
        </>
      )}

    </div>
  );
}

export function EnvironmentsPage({ data }: { data: PortalData }) {
  const rows = buildEnvironmentReadinessRows({
    targetGroups: data.targetGroups,
    runs: data.runs,
    findings: data.findings
  });
  return (
    <div className="content">
      <PageHeader route="environments" />
      <Card>
        <CardHeader>
          <CardTitle>Environment readiness</CardTitle>
          <CardDescription>Segment declared groups by operational environment and current validation evidence.</CardDescription>
        </CardHeader>
        <CardContent className="environment-grid">
          {rows.length ? rows.map((row) => (
            <div className="environment-card" key={row.id}>
              <div>
                <strong>{row.id}</strong>
                <Badge tone={row.coverage === 100 && row.openFindings === 0 ? 'success' : row.coverage > 0 ? 'warn' : 'danger'}>{row.state}</Badge>
              </div>
              <Progress value={row.coverage} />
              <span>{row.groups.length} declared target groups</span>
              <span>{row.completedRuns} completed or verdicted runs</span>
              <span>{row.openFindings} open findings</span>
            </div>
          )) : (
            <EmptyState icon={ServerCog} title="No environments yet." body="Create a declared target group with an environment ID to populate this view." actionLabel="Open Target Groups" actionHref="#target-groups" />
          )}
        </CardContent>
      </Card>
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
  const safeChecks = data.checks.filter((check) => getString(check, ['safety_class']) === 'safe');
  const socGatedChecks = data.checks.filter((check) => getString(check, ['safety_class']) === 'soc_gated');
  const policyColumns: TableColumn<DataItem>[] = [
    {
      key: 'target',
      label: 'Target group',
      render: (item) => {
        const targetGroup = item.target_group && typeof item.target_group === 'object' ? item.target_group as DataItem : {};
        return getString(targetGroup, ['name', 'id'], getString(item, ['target_group_id']));
      }
    },
    {
      key: 'check',
      label: 'Check',
      render: (item) => {
        const check = item.check && typeof item.check === 'object' ? item.check as DataItem : {};
        return getString(check, ['name', 'check_id'], getString(item, ['check_id']));
      }
    },
    { key: 'state', label: 'State', render: (item) => <Badge tone={getString(item, ['state'], 'active') === 'paused' ? 'warn' : 'success'}>{getString(item, ['state'], 'active')}</Badge> },
    { key: 'cadence', label: 'Cadence', render: (item) => <Badge tone="info">{getString(item, ['cadence'])}</Badge> },
    { key: 'expected', label: 'Expected verdict', render: (item) => getString(item, ['expected_verdict']) },
    { key: 'targets', label: 'Targets', render: (item) => getNumber(item, ['target_count']) },
    { key: 'updated', label: 'Updated', render: (item) => formatDate(item.updated_at ?? item.created_at) },
    {
      key: 'actions',
      label: 'Actions',
      render: (item) => {
        const id = getString(item, ['id'], '');
        const state = getString(item, ['state'], 'active');
        return (
          <div className="row-actions">
            <Button size="sm" variant="secondary" disabled={busy !== ''} onClick={() => void patchPolicy(id, { cadence: 'weekly' }, 'Policy cadence updated to weekly.')}>Weekly</Button>
            <Button size="sm" variant="secondary" disabled={busy !== ''} onClick={() => void patchPolicy(id, { state: state === 'paused' ? 'active' : 'paused' }, state === 'paused' ? 'Policy resumed.' : 'Policy paused.')}>
              {state === 'paused' ? 'Resume' : 'Pause'}
            </Button>
            <Button size="sm" variant="danger" disabled={busy !== ''} onClick={() => void archivePolicy(id)}>Archive</Button>
          </div>
        );
      }
    }
  ];

  async function runPolicyAction<T>(label: string, action: () => Promise<T>, success: string) {
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
      setError(payload?.message ?? payload?.error ?? (err instanceof Error ? err.message : 'Action failed.'));
      return null;
    } finally {
      setBusy('');
    }
  }

  async function handleCreatePolicy(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const formElement = event.currentTarget;
    const form = new FormData(formElement);
    const targetGroupId = String(form.get('target_group_id') ?? '').trim();
    const checkId = String(form.get('check_id') ?? '').trim();
    if (!targetGroupId || !checkId) {
      setError('Select a target group and safe check before creating a policy.');
      return;
    }
    const day = String(form.get('safe_window_day') ?? '').trim();
    const start = String(form.get('safe_window_start') ?? '').trim();
    const end = String(form.get('safe_window_end') ?? '').trim();
    const safe_windows = day && start && end
      ? [{ day, start, end, timezone: String(form.get('safe_window_timezone') ?? 'UTC').trim() || 'UTC' }]
      : [];
    const created = await runPolicyAction('create-test-policy', () => requestJson(config, session, '/v1/test-policies', {
      method: 'POST',
      body: {
        target_group_id: targetGroupId,
        check_id: checkId,
        cadence: String(form.get('cadence') ?? 'manual'),
        expected_verdict: String(form.get('expected_verdict') ?? 'pass'),
        safe_windows
      }
    }), 'Test policy created from declared scope and safe check catalog.');
    if (created) formElement.reset();
  }

  async function patchPolicy(id: string, body: Record<string, unknown>, success: string) {
    if (!id) return;
    await runPolicyAction(`patch-policy-${id}`, () => requestJson(config, session, `/v1/test-policies/${id}`, {
      method: 'PATCH',
      body
    }), success);
  }

  async function archivePolicy(id: string) {
    if (!id) return;
    await runPolicyAction(`archive-policy-${id}`, () => requestJson(config, session, `/v1/test-policies/${id}`, { method: 'DELETE' }), 'Test policy archived.');
  }

  return (
    <div className="content">
      <PageHeader route="test-policies" eyebrow="Policy binding" />
      <div className="metric-grid three">
        <MetricCard label="Active policies" value={data.testPolicies.length} sub="Tenant API policy records" icon={ClipboardList} tone="info" />
        <MetricCard label="Safe checks" value={safeChecks.length} sub="Customer-runnable catalog" icon={ListChecks} tone="success" />
        <MetricCard label="SOC-gated checks" value={socGatedChecks.length} sub="Request-only, not policy-created" icon={ShieldCheck} tone="warn" />
      </div>
      {(message || error) && (
        <div className={error ? 'form-banner error' : 'form-banner'}>{error || message}</div>
      )}
      <Card>
        <CardHeader>
          <CardTitle>Create safe validation policy</CardTitle>
          <CardDescription>Bind a customer-runnable safe check to an active declared target group. SOC-gated checks remain request-only.</CardDescription>
        </CardHeader>
        <CardContent>
          <form className="product-form" onSubmit={handleCreatePolicy}>
            <label>
              <span>Target group</span>
              <select name="target_group_id" required defaultValue="">
                <option value="">Select declared group</option>
                {data.targetGroups.map((group) => (
                  <option key={getString(group, ['id'])} value={getString(group, ['id'])}>{getString(group, ['name', 'id'])}</option>
                ))}
              </select>
            </label>
            <label>
              <span>Safe check</span>
              <select name="check_id" required defaultValue="">
                <option value="">Select safe check</option>
                {safeChecks.map((check) => (
                  <option key={getString(check, ['check_id'])} value={getString(check, ['check_id'])}>{getString(check, ['name', 'check_id'])}</option>
                ))}
              </select>
            </label>
            <label>
              <span>Cadence</span>
              <select name="cadence" defaultValue="weekly">
                <option value="manual">Manual</option>
                <option value="daily">Daily</option>
                <option value="weekly">Weekly</option>
                <option value="monthly">Monthly</option>
                <option value="event_driven">Event-driven</option>
              </select>
            </label>
            <label>
              <span>Expected verdict</span>
              <select name="expected_verdict" defaultValue="pass">
                <option value="pass">Pass</option>
                <option value="warn">Warn</option>
                <option value="fail">Fail</option>
                <option value="manual_review">Manual review</option>
              </select>
            </label>
            <label>
              <span>Safe window day</span>
              <input name="safe_window_day" placeholder="Mon" />
            </label>
            <label>
              <span>Window timezone</span>
              <input name="safe_window_timezone" defaultValue="UTC" />
            </label>
            <label>
              <span>Window start</span>
              <input name="safe_window_start" type="time" />
            </label>
            <label>
              <span>Window end</span>
              <input name="safe_window_end" type="time" />
            </label>
            <div className="form-actions full">
              <Button type="submit" disabled={busy !== '' || data.targetGroups.length === 0 || safeChecks.length === 0}>
                {busy === 'create-test-policy' ? 'Creating...' : 'Create policy'}
              </Button>
            </div>
          </form>
        </CardContent>
      </Card>
      <Card>
        <CardHeader>
          <div>
            <CardTitle>Safe validation policies</CardTitle>
            <CardDescription>All rows are `/v1/test-policies` records enriched with active target-group and check catalog metadata.</CardDescription>
          </div>
          <Badge tone="info">{data.testPolicies.length} active</Badge>
        </CardHeader>
        <CardContent>
          <DataTable
            columns={policyColumns}
            items={data.testPolicies}
            empty={<EmptyState icon={ClipboardList} title="No test policies yet." body="Create a safe validation policy after declaring target groups and reviewing the safe check catalog." />}
          />
        </CardContent>
      </Card>

    </div>
  );
}

const CONNECTOR_SNAPSHOT_KIND_OPTIONS = [
  { value: 'waf_policy', label: 'WAF policy' },
  { value: 'cdn_property', label: 'CDN property' },
  { value: 'dns_zone', label: 'DNS zone' },
  { value: 'cloud_asset', label: 'Cloud asset' },
  { value: 'vulnerability', label: 'Vulnerability' }
] as const;

export function IntegrationPage({
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
  const [selectedConnectorId, setSelectedConnectorId] = useState('');
  const [snapshots, setSnapshots] = useState<DataItem[]>([]);
  const [busy, setBusy] = useState('');
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');
  const featureFlags = data.deploymentFeatures as { connectors?: boolean; waf_posture?: boolean } | null;
  const connectorsEnabled = featureFlags?.connectors === true;
  const activeConnectors = data.connectors.filter(
    (connector) => getString(connector, ['status'], '').toLowerCase() !== 'disabled'
  );
  const selectedConnector =
    activeConnectors.find((connector) => getString(connector, ['id'], '') === selectedConnectorId) ?? activeConnectors[0];
  const effectiveConnectorId = getString(selectedConnector ?? {}, ['id'], '');

  const connectorColumns: TableColumn<DataItem>[] = [
    { key: 'name', label: 'Connector', render: (item) => getString(item, ['name', 'id']) },
    { key: 'provider', label: 'Provider', render: (item) => <Badge tone="info">{getString(item, ['provider'])}</Badge> },
    { key: 'status', label: 'Status', render: (item) => <Badge tone={getString(item, ['status']) === 'active' ? 'success' : getString(item, ['status']) === 'error' ? 'danger' : 'muted'}>{getString(item, ['status'])}</Badge> },
    { key: 'secret', label: 'Secret ref', render: (item) => getString(item, ['secret_id'], 'manual snapshots only') },
    { key: 'updated', label: 'Updated', render: (item) => formatDate(item.updated_at ?? item.created_at) },
    {
      key: 'actions',
      label: 'Actions',
      render: (item) => {
        const id = getString(item, ['id'], '');
        const status = getString(item, ['status'], '').toLowerCase();
        const isDisabled = status === 'disabled';
        return (
          <div className="row-actions">
            <Button size="sm" variant="secondary" disabled={busy !== '' || isDisabled} onClick={() => void validateConnector(id)}>Validate</Button>
            <Button size="sm" variant="secondary" disabled={busy !== '' || isDisabled} onClick={() => void pollConnector(id)}>Poll</Button>
            <Button size="sm" variant="ghost" disabled={busy !== ''} onClick={() => void loadSnapshots(id)}>Snapshots</Button>
            <Button size="sm" variant="danger" disabled={busy !== '' || isDisabled} onClick={() => void disableConnector(id)}>Disable</Button>
          </div>
        );
      }
    }
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
      setError(payload?.message ?? payload?.error ?? (err instanceof Error ? err.message : 'Action failed.'));
      return null;
    } finally {
      setBusy('');
    }
  }

  async function handleCreateConnector(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const formElement = event.currentTarget;
    const form = new FormData(formElement);
    const provider = String(form.get('provider') ?? 'cloudflare');
    const name = String(form.get('name') ?? '').trim();
    const secretInput = String(form.get('secret') ?? '').trim();
    const externalSecretId = String(form.get('secret_id') ?? '').trim();
    const resourceRefHash = String(form.get('resource_ref_hash') ?? '').trim();
    const region = String(form.get('region') ?? '').trim();
    const defaultSnapshotKind = String(form.get('default_snapshot_kind') ?? 'waf_policy');
    if (!name) {
      setError('Connector name is required.');
      return;
    }
    await runAction('create-connector', async () => {
      let secretId = externalSecretId || null;
      if (secretInput) {
        const stored = await requestJson(config, session, '/v1/secrets', {
          method: 'POST',
          body: {
            purpose: 'waf_connector',
            name: `${provider}:${name}`,
            plaintext: secretInput,
            metadata: { provider, read_only: true }
          }
        }) as { secret?: { id?: string } };
        secretId = stored.secret?.id ?? null;
      }
      const created = await requestJson(config, session, '/v1/connectors', {
        method: 'POST',
        body: {
          provider,
          name,
          ...(secretId ? { secret_id: secretId } : {}),
          status: 'active',
          config: {
            read_only: true,
            default_snapshot_kind: defaultSnapshotKind,
            ...(provider === 'cloudflare' && resourceRefHash ? { zone_ref_hash: resourceRefHash } : {}),
            ...(provider === 'aws_waf' && resourceRefHash ? { resource_ref_hash: resourceRefHash } : {}),
            ...(provider === 'aws_waf' && region ? { region_summary: region } : {})
          }
        }
      }) as { connector?: DataItem };
      formElement.reset();
      if (created.connector?.id) setSelectedConnectorId(String(created.connector.id));
      return created;
    }, 'Connector created from backend API.');
  }

  async function validateConnector(id: string) {
    if (!id) return;
    await runAction(`validate-${id}`, () => requestJson(config, session, `/v1/connectors/${id}/validate`, { method: 'POST' }), 'Connector validation completed.');
  }

  async function pollConnector(id: string) {
    if (!id) return;
    const result = await runAction(`poll-${id}`, () => requestJson(config, session, `/v1/connectors/${id}/poll`, { method: 'POST', body: {} }), 'Connector poll requested.');
    const nextSnapshots = result && typeof result === 'object' && 'snapshots' in result ? (result as { snapshots?: DataItem[] }).snapshots : null;
    if (Array.isArray(nextSnapshots)) setSnapshots(nextSnapshots);
  }

  async function disableConnector(id: string) {
    if (!id) return;
    await runAction(`disable-${id}`, () => requestJson(config, session, `/v1/connectors/${id}/disable`, { method: 'POST', body: { reason: 'Disabled from integrations page.' } }), 'Connector disabled.');
  }

  async function loadSnapshots(id: string) {
    if (!id) return;
    const result = await runAction(`snapshots-${id}`, () => requestJson(config, session, `/v1/connectors/${id}/snapshots`), 'Connector snapshots loaded.');
    const items = result && typeof result === 'object' && 'items' in result ? (result as { items?: DataItem[] }).items : null;
    setSnapshots(Array.isArray(items) ? items : []);
    setSelectedConnectorId(id);
  }

  async function handleManualSnapshot(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const formElement = event.currentTarget;
    const id = effectiveConnectorId;
    if (!id) {
      setError('Create or select a connector before adding a snapshot.');
      return;
    }
    const form = new FormData(formElement);
    const hostnames = String(form.get('hostnames') ?? '')
      .split(',')
      .map((value) => value.trim())
      .filter(Boolean);
    const ruleCount = Number(form.get('rule_count') ?? 0);
    const snapshot = {
      snapshot_kind: String(form.get('snapshot_kind') ?? 'waf_policy'),
      display_ref: String(form.get('display_ref') ?? '').trim(),
      resource_ref_hash: String(form.get('resource_ref_hash') ?? '').trim(),
      config_hash: String(form.get('config_hash') ?? '').trim(),
      summary: {
        policy_mode: String(form.get('policy_mode') ?? 'monitor'),
        rule_count: Number.isFinite(ruleCount) ? ruleCount : 0,
        ...(hostnames.length ? { hostnames } : {})
      }
    };
    if (!snapshot.display_ref || !snapshot.resource_ref_hash || !snapshot.config_hash) {
      setError('Display ref, resource hash, and config hash are required for a metadata snapshot.');
      return;
    }
    const result = await runAction(
      `snapshot-${id}`,
      () => requestJson(config, session, `/v1/connectors/${id}/poll`, { method: 'POST', body: { manual_only: true, snapshots: [snapshot] } }),
      'Manual connector snapshot ingested.'
    );
    const nextSnapshots = result && typeof result === 'object' && 'snapshots' in result ? (result as { snapshots?: DataItem[] }).snapshots : null;
    if (Array.isArray(nextSnapshots)) setSnapshots(nextSnapshots);
    formElement.reset();
  }

  return (
    <div className="content">
      <PageHeader route="integrations" eyebrow="Connectors" />
      <div className="metric-grid three">
        <MetricCard label="Connectors" value={data.connectors.length} sub={connectorsEnabled ? 'Tenant feature enabled' : 'Feature flag disabled'} icon={PlugZap} tone={connectorsEnabled ? 'success' : 'muted'} />
        <MetricCard label="Secret refs" value={data.secrets.length} sub="Redacted vault entries visible to this role" icon={KeyRound} tone="info" />
        <MetricCard label="WAF posture" value={featureFlags?.waf_posture ? 'on' : 'off'} sub="Optional posture enrichment" icon={ShieldCheck} tone={featureFlags?.waf_posture ? 'success' : 'muted'} />
      </div>
      {!connectorsEnabled ? (
        <Card>
          <CardHeader>
            <CardTitle>Connectors are disabled for this tenant</CardTitle>
            <CardDescription>Enable `ASTRANULL_WAF_POSTURE_ENABLED=1` and `ASTRANULL_CONNECTORS_ENABLED=1`, or grant a tenant override, to manage read-only connectors.</CardDescription>
          </CardHeader>
          <CardContent className="callout-list">
            <div className="callout info"><ShieldCheck size={18} /><span>Core DDoS validation still works from declared target groups without cloud credentials.</span></div>
            <div className="callout"><FileCheck2 size={18} /><span>Connector credentials must be stored as encrypted secret references before provider polling.</span></div>
          </CardContent>
        </Card>
      ) : (
        <>
          <div className="split">
            <Card>
              <CardHeader>
                <CardTitle>Create read-only connector</CardTitle>
                <CardDescription>Store a provider credential in the secret vault or reference an existing secret, then create a metadata-only connector.</CardDescription>
              </CardHeader>
              <CardContent>
                <form className="product-form" onSubmit={handleCreateConnector}>
                  <label>
                    <span>Provider</span>
                    <select name="provider" defaultValue="cloudflare">
                      <option value="cloudflare">Cloudflare</option>
                      <option value="aws_waf">AWS WAF</option>
                    </select>
                  </label>
                  <label>
                    <span>Name</span>
                    <input name="name" placeholder="edge-readonly" required />
                  </label>
                  <label className="full">
                    <span>API key or credential JSON</span>
                    <textarea name="secret" rows={4} placeholder='Cloudflare token, or AWS JSON: {"access_key_id":"...","secret_access_key":"...","region":"us-east-1"}' />
                  </label>
                  <label>
                    <span>Existing secret ref</span>
                    <input name="secret_id" placeholder="secret_..." />
                  </label>
                  <label>
                    <span>Resource hash</span>
                    <input name="resource_ref_hash" placeholder="Optional zone/web ACL hash" />
                  </label>
                  <label>
                    <span>AWS region</span>
                    <input name="region" placeholder="us-east-1" />
                  </label>
                  <label>
                    <span>Snapshot kind</span>
                    <select name="default_snapshot_kind" defaultValue="waf_policy">
                      {CONNECTOR_SNAPSHOT_KIND_OPTIONS.map((option) => (
                        <option key={option.value} value={option.value}>{option.label}</option>
                      ))}
                    </select>
                  </label>
                  <div className="form-actions full">
                    <Button disabled={busy !== ''} type="submit">{busy === 'create-connector' ? 'Creating...' : 'Create connector'}</Button>
                  </div>
                </form>
              </CardContent>
            </Card>
            <Card>
              <CardHeader>
                <CardTitle>Manual metadata snapshot</CardTitle>
                <CardDescription>Use this when provider polling is unavailable or encryption is not configured locally.</CardDescription>
              </CardHeader>
              <CardContent>
                <form className="product-form" onSubmit={handleManualSnapshot}>
                  <label className="full">
                    <span>Connector</span>
                    <select value={effectiveConnectorId} onChange={(event) => setSelectedConnectorId(event.target.value)}>
                      {activeConnectors.map((connector) => (
                        <option key={getString(connector, ['id'])} value={getString(connector, ['id'])}>
                          {getString(connector, ['name'])} - {getString(connector, ['provider'])}
                        </option>
                      ))}
                    </select>
                  </label>
                  <label>
                    <span>Snapshot kind</span>
                    <select name="snapshot_kind" defaultValue="waf_policy">
                      {CONNECTOR_SNAPSHOT_KIND_OPTIONS.map((option) => (
                        <option key={option.value} value={option.value}>{option.label}</option>
                      ))}
                    </select>
                  </label>
                  <label>
                    <span>Display ref</span>
                    <input name="display_ref" placeholder="zone-a" required />
                  </label>
                  <label>
                    <span>Resource hash</span>
                    <input name="resource_ref_hash" placeholder="res_hash_1" required />
                  </label>
                  <label>
                    <span>Config hash</span>
                    <input name="config_hash" placeholder="cfg_hash_1" required />
                  </label>
                  <label>
                    <span>Policy mode</span>
                    <select name="policy_mode" defaultValue="monitor">
                      <option value="block">Block</option>
                      <option value="monitor">Monitor</option>
                      <option value="unknown">Unknown</option>
                    </select>
                  </label>
                  <label>
                    <span>Rule count</span>
                    <input name="rule_count" type="number" min="0" defaultValue="0" />
                  </label>
                  <label className="full">
                    <span>Hostnames</span>
                    <input name="hostnames" placeholder="app.example.com, api.example.com" />
                  </label>
                  <div className="form-actions full">
                    <Button disabled={busy !== '' || !effectiveConnectorId} type="submit">Ingest snapshot</Button>
                  </div>
                </form>
              </CardContent>
            </Card>
          </div>
          {(message || error) && (
            <div className={error ? 'form-banner error' : 'form-banner'}>
              {error || message}
            </div>
          )}
          <Card>
            <CardHeader>
              <div>
                <CardTitle>Configured connectors</CardTitle>
                <CardDescription>Actions call `/v1/connectors` and never render plaintext credentials.</CardDescription>
              </div>
              <Badge tone="info">{data.connectors.length} total</Badge>
            </CardHeader>
            <CardContent>
              <DataTable
                columns={connectorColumns}
                items={data.connectors}
                empty={<EmptyState icon={PlugZap} title="No connectors configured." body="Create a read-only connector or continue using manual evidence workflows without provider access." />}
              />
            </CardContent>
          </Card>
          <Card>
            <CardHeader>
              <div>
                <CardTitle>Connector snapshots</CardTitle>
                <CardDescription>Snapshots come from backend poll results or manual metadata ingest.</CardDescription>
              </div>
              <Badge tone="muted">{snapshots.length} loaded</Badge>
            </CardHeader>
            <CardContent className="queue-list">
              {snapshots.length === 0 ? (
                <EmptyState icon={FileCheck2} title="No snapshots loaded." body="Select a connector action to load or ingest metadata snapshots." />
              ) : snapshots.map((snapshot) => (
                <div key={getString(snapshot, ['id'])}>
                  <Badge tone="info">{getString(snapshot, ['snapshot_kind'])}</Badge>
                  <span>{getString(snapshot, ['display_ref'])} - {formatDate(snapshot.observed_at ?? snapshot.created_at)}</span>
                </div>
              ))}
            </CardContent>
          </Card>
        </>
      )}
    </div>
  );
}

export function SupportPage({ data, session }: { data: PortalData; session: Session }) {
  const summary = data.subscriptionSummary;
  const support = getNestedItem(summary, ['support']);
  const usage = getNestedItem(summary, ['usage']);
  const account = getNestedItem(summary, ['account']);
  const recentAudit = getNestedArray(support, ['recent_audit']);
  const openFindings = getNumber(usage ?? {}, ['open_findings']);
  const pendingHighScale = getNumber(usage ?? {}, ['pending_high_scale_requests']);
  const supportOwner = getString(support ?? {}, ['owner'], 'Unassigned');
  const escalationState = getString(support ?? {}, ['escalation_state'], summary ? 'nominal' : 'No record');
  const killSwitchActive = Boolean(data.state?.kill_switch?.active ?? data.state?.kill_switch?.enabled);
  const routeAccessContext = {
    principal: session.principal,
    staffRole: session.staff_role,
  };
  const role = session.role ?? 'admin';
  const canReadNotifications = canAccessRoute(role, 'notifications', routeAccessContext);
  const canReadReleaseEvidence = canAccessRoute(role, 'release-evidence', routeAccessContext);
  const supportReadiness = data.releaseEvidence.find((item) => getString(item, ['kind']) === 'support_readiness') ?? null;

  const supportRows = summary
    ? [
        { label: 'Support owner', value: supportOwner, icon: LifeBuoy },
        { label: 'Account lifecycle', value: getString(account ?? support ?? {}, ['lifecycle_state'], 'unrecorded'), icon: ShieldCheck },
        { label: 'Region', value: getString(account ?? support ?? {}, ['region'], 'unrecorded'), icon: Network },
        { label: 'Recent tenant audit records', value: formatNumber(getNumber(usage ?? {}, ['audit_events'])), icon: FileCheck2 }
      ]
    : [];

  return (
    <div className="content">
      <PageHeader route="support" eyebrow="Readiness support" />
      <div className="metric-grid three">
        <MetricCard label="Support owner" value={supportOwner} sub="From tenant account metadata" icon={LifeBuoy} tone={supportOwner === 'Unassigned' ? 'muted' : 'info'} />
        <MetricCard label="Open findings" value={openFindings} sub="Tenant-scoped finding records" icon={TriangleAlert} tone={openFindings > 0 ? 'warn' : 'success'} />
        <MetricCard label="SOC escalations" value={pendingHighScale} sub={escalationState.replaceAll('_', ' ')} icon={Siren} tone={pendingHighScale > 0 ? 'warn' : 'success'} />
      </div>
      <div className="split">
        <Card>
          <CardHeader>
            <CardTitle>Support readiness</CardTitle>
            <CardDescription>Tenant support posture from account, findings, high-scale, and audit records.</CardDescription>
          </CardHeader>
          <CardContent className="settings-list">
            {supportRows.length === 0 ? (
              <EmptyState icon={LifeBuoy} title="No support account record." body="Approve a signup request or attach tenant account metadata before support readiness can show live ownership." />
            ) : supportRows.map(({ label, value, icon: Icon }) => (
              <div key={label}><Icon size={18} /><span>{label}: <strong>{value}</strong></span></div>
            ))}
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>Recent support evidence</CardTitle>
            <CardDescription>Latest tenant audit events exposed as metadata-only support context.</CardDescription>
          </CardHeader>
          <CardContent className="queue-list">
            {recentAudit.length === 0 ? (
              <EmptyState icon={FileCheck2} title="No recent support evidence." body="Tenant audit entries will appear here after support-relevant actions are recorded." />
            ) : recentAudit.map((entry) => (
              <div key={getString(entry, ['id', 'created_at', 'action'])}>
                <Badge tone="info">{getString(entry, ['resource_type'], 'audit')}</Badge>
                <span>{getString(entry, ['action'])} - {formatDate(entry.created_at)}</span>
              </div>
            ))}
          </CardContent>
        </Card>
      </div>
      <Card>
        <CardHeader>
          <CardTitle>Support workflows</CardTitle>
          <CardDescription>Customer-safe escalation paths that stay within governed validation boundaries.</CardDescription>
        </CardHeader>
        <CardContent className="row-actions">
          <AnchorButton href="#findings" variant="secondary" size="sm">Review open findings ({openFindings})</AnchorButton>
          <AnchorButton href="#high-scale" variant="secondary" size="sm">Request SOC-governed test ({pendingHighScale} pending)</AnchorButton>
          {canReadNotifications ? <AnchorButton href="#notifications" variant="secondary" size="sm">Notification rules</AnchorButton> : null}
          {canReadReleaseEvidence ? <AnchorButton href="#release-evidence" variant="ghost" size="sm">Release evidence</AnchorButton> : null}
        </CardContent>
        <CardContent className="kv-list">
          <div><span>Kill switch</span><strong>{killSwitchActive ? 'Active' : 'Inactive'}</strong></div>
          <div><span>Support readiness evidence</span><strong>{supportReadiness ? getString(supportReadiness, ['status'], 'recorded') : 'Not indexed'}</strong></div>
          <div><span>Escalation state</span><strong>{escalationState.replaceAll('_', ' ')}</strong></div>
        </CardContent>
      </Card>
    </div>
  );
}

const ENTITLEMENT_FEATURES = ['waf_posture', 'external_discovery', 'connectors', 'high_scale_program'] as const;

const ENTITLEMENT_FEATURE_LABELS: Record<(typeof ENTITLEMENT_FEATURES)[number], string> = {
  waf_posture: 'WAF posture',
  external_discovery: 'External discovery',
  connectors: 'Connectors',
  high_scale_program: 'High-scale program'
};

function formatEntitlementGrantSource(value: string) {
  if (!value || value === 'plan only') return 'Plan default';
  if (value.startsWith('plan:')) return `Plan default (${value.slice(5)})`;
  return value;
}

function usageMeter(label: string, used: number, limit: number) {
  const hasLimit = limit >= 0;
  const percent = hasLimit && limit > 0 ? Math.min(100, Math.round((used / limit) * 100)) : 0;
  return (
    <div className="factor" key={label}>
      <div>
        <strong>{label}</strong>
        <span>{hasLimit ? `${used} / ${limit}` : `${used} recorded`}</span>
      </div>
      <Badge tone={hasLimit && used >= limit ? 'warn' : 'info'}>{hasLimit ? `${percent}%` : 'unlimited'}</Badge>
      {hasLimit ? <Progress value={percent} /> : null}
    </div>
  );
}

export function SubscriptionPage({ data }: { data: PortalData }) {
  const summary = data.subscriptionSummary;
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
  const safeRunsLimit = getNestedNumber(subscription, ['limits', 'safe_runs_per_hour'], -1);
  const safeRunsUsed = getNumber(usage ?? {}, ['safe_runs_started_last_hour']);
  const highScaleEnabled = effectiveEntitlements?.high_scale_program === true;
  const targetGroupLimit = getNestedNumber(subscription, ['limits', 'target_groups'], -1);
  const targetGroupUsage = getNumber(usage ?? {}, ['target_groups']);
  const usersLimit = getNestedNumber(subscription, ['limits', 'users'], -1);
  const agentsLimit = getNestedNumber(subscription, ['limits', 'agents'], -1);
  const supportOwner = getString(support ?? account ?? {}, ['owner', 'support_owner'], '');

  return (
    <div className="content">
      <PageHeader route="subscription" eyebrow="Entitlements" />
      {!hasSubscription ? (
        <EmptyState
          icon={LifeBuoy}
          title="No subscription configured for this tenant."
          body="AstraNull did not return a tenant subscription from `/v1/subscription/current`. Limits, entitlements, and billing metadata stay hidden until staff provisioning completes. Contact your AstraNull support team through the Support page for provisioning or billing assistance."
          actionLabel="Open Support"
          actionHref="#support"
        />
      ) : null}
      <div className="metric-grid three">
        <MetricCard
          label="Plan"
          value={planLabel}
          sub={hasSubscription ? getString(subscription ?? {}, ['status'], 'status unknown') : 'No tenant subscription record'}
          icon={KeyRound}
          tone={hasSubscription ? 'info' : 'muted'}
        />
        <MetricCard
          label="Safe-run cap"
          value={hasSubscription && safeRunsLimit >= 0 ? safeRunsLimit : '—'}
          sub={hasSubscription ? `${safeRunsUsed} started in the last hour` : 'Limits appear after subscription provisioning'}
          icon={ListChecks}
          tone={hasSubscription && safeRunsLimit >= 0 && safeRunsUsed >= safeRunsLimit ? 'warn' : hasSubscription ? 'success' : 'muted'}
        />
        <MetricCard
          label="High-scale program"
          value={hasSubscription ? (highScaleEnabled ? 'Enabled' : 'Disabled') : '—'}
          sub={hasSubscription ? 'Execution remains SOC-gated' : 'Entitlement unavailable without subscription'}
          icon={ShieldCheck}
          tone={highScaleEnabled ? 'warn' : 'muted'}
        />
      </div>
      <div className="split">
        <Card>
          <CardHeader>
            <CardTitle>Contract posture</CardTitle>
            <CardDescription>Billing metadata, entitlement limits, and account state from `/v1/subscription/current`.</CardDescription>
          </CardHeader>
          <CardContent className={hasSubscription ? 'kv-list' : ''}>
            {!hasSubscription ? (
              <EmptyState
                icon={KeyRound}
                title="Contract details unavailable."
                body="Region, lifecycle, renewal, and support-owner metadata appear after a subscription record exists. Use the Support page to contact your AstraNull support team."
                actionLabel="Contact support"
                actionHref="#support"
              />
            ) : (
              <>
                <div><span>Status</span><strong>{getString(subscription ?? {}, ['status'])}</strong></div>
                <div><span>Effective</span><strong>{formatDate(subscription?.effective_at)}</strong></div>
                <div><span>Renewal</span><strong>{formatDate(subscription?.renewal_at)}</strong></div>
                <div><span>Data region</span><strong>{getString(account ?? support ?? {}, ['region'], 'unrecorded')}</strong></div>
                <div><span>Lifecycle</span><strong>{getString(account ?? support ?? {}, ['lifecycle_state'], 'unrecorded')}</strong></div>
                <div><span>Support owner</span><strong>{getString(account ?? {}, ['support_owner'], supportOwner || 'unassigned')}</strong></div>
                <div><span>Contract ref</span><strong>{getString(account ?? {}, ['contract_reference'], 'unrecorded')}</strong></div>
              </>
            )}
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>Usage against limits</CardTitle>
            <CardDescription>Live workspace counts compared to subscription limits.</CardDescription>
          </CardHeader>
          <CardContent className="factor-list">
            {!hasSubscription ? (
              <EmptyState
                icon={ListChecks}
                title="Usage meters unavailable."
                body="Safe-run caps, target-group limits, and workspace usage comparisons require a provisioned subscription. Contact support if provisioning should already be complete."
                actionLabel="Open Support"
                actionHref="#support"
              />
            ) : (
              <>
                {usageMeter('Target groups', targetGroupUsage, targetGroupLimit)}
                {usageMeter('Users', getNumber(usage ?? {}, ['users']), usersLimit)}
                {usageMeter('Agents', getNumber(usage ?? {}, ['agents']), agentsLimit)}
                {usageMeter('Safe runs / hour', safeRunsUsed, safeRunsLimit)}
                <div className="factor">
                  <div><strong>Open findings</strong><span>{getNumber(usage ?? {}, ['open_findings'])} active records</span></div>
                  <Badge tone={getNumber(usage ?? {}, ['open_findings']) > 0 ? 'warn' : 'success'}>{getNumber(usage ?? {}, ['open_findings'])}</Badge>
                </div>
                <div className="factor">
                  <div><strong>Pending high-scale</strong><span>{getNumber(usage ?? {}, ['pending_high_scale_requests'])} awaiting SOC workflow</span></div>
                  <Badge tone={getNumber(usage ?? {}, ['pending_high_scale_requests']) > 0 ? 'warn' : 'muted'}>{getNumber(usage ?? {}, ['pending_high_scale_requests'])}</Badge>
                </div>
              </>
            )}
          </CardContent>
        </Card>
      </div>
      <Card>
        <CardHeader>
          <CardTitle>Entitlement breakdown</CardTitle>
          <CardDescription>Plan defaults, staff grants, and effective feature access for this tenant.</CardDescription>
        </CardHeader>
        <CardContent>
          {!hasSubscription ? (
            <EmptyState
              icon={ShieldCheck}
              title="No entitlements to display."
              body="Feature entitlements are computed after a subscription record exists. Open Support to request plan provisioning or entitlement review."
              actionLabel="Open Support"
              actionHref="#support"
            />
          ) : (
            <DataTable
              columns={[
                {
                  key: 'feature',
                  label: 'Feature',
                  render: (item) => {
                    const feature = getString(item, ['feature']);
                    return ENTITLEMENT_FEATURE_LABELS[feature as (typeof ENTITLEMENT_FEATURES)[number]] ?? feature;
                  }
                },
                {
                  key: 'plan',
                  label: 'Plan default',
                  render: (item) => (
                    <Badge tone={item.plan_enabled === true ? 'success' : 'muted'}>
                      {item.plan_enabled === true ? 'enabled' : 'disabled'}
                    </Badge>
                  )
                },
                {
                  key: 'effective',
                  label: 'Effective',
                  render: (item) => (
                    <Badge tone={item.effective_enabled === true ? 'success' : 'warn'}>
                      {item.effective_enabled === true ? 'enabled' : 'disabled'}
                    </Badge>
                  )
                },
                {
                  key: 'grant',
                  label: 'Grant source',
                  render: (item) => formatEntitlementGrantSource(getString(item, ['grant_source'], 'plan only'))
                }
              ]}
              items={ENTITLEMENT_FEATURES.map((feature) => {
                const grant = entitlementGrants.find((entry) => getString(entry, ['feature'], '') === feature);
                return {
                  feature,
                  plan_enabled: planEntitlements?.[feature] === true,
                  effective_enabled: effectiveEntitlements?.[feature] === true,
                  grant_source: grant ? getString(grant, ['source'], 'staff grant') : 'plan only'
                };
              })}
              empty={<EmptyState icon={ShieldCheck} title="No entitlement features." body="Plan feature entitlements were not returned by the subscription API." />}
            />
          )}
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
  const [busy, setBusy] = useState('');
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');
  const [entitlementTenantId, setEntitlementTenantId] = useState(() => getString(data.internalTenants[0] ?? {}, ['tenant_id', 'id'], 'ten_demo'));
  const [subscriptionSnapshot, setSubscriptionSnapshot] = useState<DataItem | null>(null);
  const entitlementFeatures = ['waf_posture', 'external_discovery', 'connectors', 'high_scale_program'] as const;
  const isStaff = session.principal === 'staff';
  const overview = data.internalOverview;
  const queueDepth = getNumber(overview ?? {}, ['pending_signups']) + getNumber(overview ?? {}, ['pending_approval_requests']);
  const tenantCount = getNumber(overview ?? {}, ['tenant_count'], data.internalTenants.length);
  const highScaleReviews = getNumber(overview ?? {}, ['high_scale_reviews']);
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
      const payload = (err as Error & { payload?: unknown }).payload as { error?: string; message?: string } | undefined;
      setError(payload?.message ?? payload?.error ?? (err instanceof Error ? err.message : 'Staff action failed.'));
      return null;
    } finally {
      setBusy('');
    }
  }

  async function approveSignup(id: string) {
    await runStaffAction(`approve-signup-${id}`, () => requestJson(config, session, `/internal/admin/signup-requests/${id}/approve`, {
      method: 'POST',
      body: { reason: 'Approved from React staff console.' }
    }), 'Signup request approved and tenant provisioned.');
  }

  async function rejectSignup(id: string) {
    await runStaffAction(`reject-signup-${id}`, () => requestJson(config, session, `/internal/admin/signup-requests/${id}/reject`, {
      method: 'POST',
      body: { reason: 'Rejected from React staff console.' }
    }), 'Signup request rejected.');
  }

  async function patchTenant(tenantId: string, lifecycleState: string) {
    await runStaffAction(`patch-tenant-${tenantId}`, () => requestJson(config, session, `/internal/admin/tenants/${tenantId}`, {
      method: 'PATCH',
      body: { lifecycle_state: lifecycleState, reason: `Lifecycle set to ${lifecycleState} from React staff console.` }
    }), `Tenant lifecycle updated to ${lifecycleState}.`);
  }

  async function decideApproval(id: string, decision: 'approve' | 'reject') {
    await runStaffAction(`approval-${id}-${decision}`, () => requestJson(config, session, `/internal/admin/approval-requests/${id}/decision`, {
      method: 'POST',
      body: { decision, reason: `${decision} from React staff console.` }
    }), `Approval request ${decision}d.`);
  }

  useEffect(() => {
    if (!isStaff || !entitlementTenantId) {
      setSubscriptionSnapshot(null);
      return;
    }
    let cancelled = false;
    requestJson(config, session, `/internal/admin/tenants/${encodeURIComponent(entitlementTenantId)}/subscription`)
      .then((payload) => {
        if (!cancelled) setSubscriptionSnapshot(payload as DataItem);
      })
      .catch(() => {
        if (!cancelled) setSubscriptionSnapshot(null);
      });
    return () => {
      cancelled = true;
    };
  }, [config, session, entitlementTenantId, isStaff, data.internalTenants]);

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
    await runStaffAction(`entitlement-${entitlementTenantId}-${feature}`, () => requestJson(config, session, `/internal/admin/tenants/${encodeURIComponent(entitlementTenantId)}/entitlements`, {
      method: 'POST',
      body: { feature, enabled, reason: reason || `Entitlement ${enabled ? 'granted' : 'revoked'} from React staff console.` }
    }), `${feature} entitlement ${enabled ? 'granted' : 'revoked'} for ${entitlementTenantId}.`);
  }

  const effectiveEntitlements = getNestedItem(subscriptionSnapshot, ['effective_entitlements'])
    ?? getNestedItem(subscriptionSnapshot, ['subscription', 'effective_entitlements']);

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
        if (!['submitted', 'under_review'].includes(state)) return '—';
        return (
          <div className="row-actions">
            <Button size="sm" variant="secondary" disabled={busy !== ''} onClick={() => void approveSignup(id)}>Approve</Button>
            <Button size="sm" variant="danger" disabled={busy !== ''} onClick={() => void rejectSignup(id)}>Reject</Button>
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
        const lifecycle = getString(item, ['lifecycle_state'], 'active');
        return (
          <div className="row-actions">
            <AnchorButton size="sm" variant="secondary" href={buildDetailHref('tenant-detail', tenantId)}>Detail</AnchorButton>
            {lifecycle !== 'active' ? <Button size="sm" variant="secondary" disabled={busy !== ''} onClick={() => void patchTenant(tenantId, 'active')}>Activate</Button> : null}
            {lifecycle === 'active' ? <Button size="sm" variant="danger" disabled={busy !== ''} onClick={() => void patchTenant(tenantId, 'suspended')}>Suspend</Button> : null}
          </div>
        );
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
        if (!['submitted', 'under_review'].includes(state)) return '—';
        return (
          <div className="row-actions">
            <Button size="sm" variant="secondary" disabled={busy !== ''} onClick={() => void decideApproval(id, 'approve')}>Approve</Button>
            <Button size="sm" variant="danger" disabled={busy !== ''} onClick={() => void decideApproval(id, 'reject')}>Reject</Button>
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
      <PageHeader route={route} eyebrow={route === 'internal-soc' ? 'Staff SOC surface' : 'Staff-only surface'} />
      {(message || error) && <div className={error ? 'form-banner error' : 'form-banner'}>{error || message}</div>}
      <div className="metric-grid three">
        <MetricCard label="Review queue" value={queueDepth} sub="Signups plus internal approvals" icon={ClipboardList} tone={queueDepth > 0 ? 'warn' : 'success'} />
        <MetricCard label="Managed tenants" value={tenantCount} sub="Internal management directory" icon={Target} tone="info" />
        <MetricCard label="SOC reviews" value={highScaleReviews} sub="High-scale requests awaiting staff workflow" icon={ShieldCheck} tone={highScaleReviews > 0 ? 'warn' : 'success'} />
      </div>
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
          <div className="split">
            <Card>
              <CardHeader>
                <CardTitle>Signup queue</CardTitle>
                <CardDescription>Requests from the staff-only signup review API.</CardDescription>
              </CardHeader>
              <CardContent>
                <DataTable columns={signupColumns} items={data.internalSignupRequests} empty={<EmptyState icon={ClipboardList} title="No signup requests." body="Reviewed account intake records will appear here after customers submit requests." />} />
              </CardContent>
            </Card>
            <Card>
              <CardHeader>
                <CardTitle>Tenant directory</CardTitle>
                <CardDescription>Managed tenant account and subscription metadata.</CardDescription>
              </CardHeader>
              <CardContent>
                <DataTable columns={tenantColumns} items={data.internalTenants} empty={<EmptyState icon={Target} title="No managed tenants." body="Provisioned tenants appear here after staff approval creates account records." />} />
              </CardContent>
            </Card>
          </div>
          <div className="split">
            <Card>
              <CardHeader>
                <CardTitle>Approval requests</CardTitle>
                <CardDescription>Unified internal approvals, including subscription exceptions.</CardDescription>
              </CardHeader>
              <CardContent>
                <DataTable columns={approvalColumns} items={data.internalApprovalRequests} empty={<EmptyState icon={ShieldCheck} title="No internal approvals." body="Pending approval records will appear here when backend workflows create them." />} />
              </CardContent>
            </Card>
            <Card>
              <CardHeader>
                <CardTitle>Internal audit</CardTitle>
                <CardDescription>Recent staff actions from the internal audit API.</CardDescription>
              </CardHeader>
              <CardContent>
                <DataTable columns={auditColumns} items={data.internalAudit} empty={<EmptyState icon={FileCheck2} title="No internal audit events." body="Staff decisions and support actions will be listed after they are recorded." />} />
              </CardContent>
            </Card>
          </div>
          <Card>
            <CardHeader>
              <CardTitle>Support owner assignment</CardTitle>
              <CardDescription>Patch tenant support owner through `/internal/admin/tenants/:id`.</CardDescription>
            </CardHeader>
            <CardContent>
              <form className="product-form" onSubmit={(event) => {
                event.preventDefault();
                const owner = String(new FormData(event.currentTarget).get('support_owner') ?? '').trim();
                if (!entitlementTenantId || !owner) return;
                void runStaffAction(`support-owner-${entitlementTenantId}`, () => requestJson(config, session, `/internal/admin/tenants/${encodeURIComponent(entitlementTenantId)}`, {
                  method: 'PATCH',
                  body: { support_owner: owner, reason: 'Support owner updated from React staff console.' }
                }), `Support owner updated for ${entitlementTenantId}.`);
              }}>
                <label><span>Tenant</span>
                  <select name="tenant_id" value={entitlementTenantId} onChange={(event) => setEntitlementTenantId(event.target.value)}>
                    {data.internalTenants.map((tenant) => {
                      const tenantId = getString(tenant, ['tenant_id', 'id'], '');
                      return <option key={tenantId} value={tenantId}>{getString(tenant, ['name', 'tenant_id'], tenantId)}</option>;
                    })}
                  </select>
                </label>
                <label className="full"><span>Support owner</span><input name="support_owner" placeholder="owner@customer.example" required /></label>
                <div className="form-actions full"><Button type="submit" disabled={busy !== ''}>Assign support owner</Button></div>
              </form>
            </CardContent>
          </Card>
          <Card>
            <CardHeader>
              <CardTitle>Entitlement grants</CardTitle>
              <CardDescription>Grant or revoke plan feature entitlements through `/internal/admin/tenants/:id/entitlements`.</CardDescription>
            </CardHeader>
            <CardContent className="product-form">
              <label>
                <span>Tenant</span>
                <select value={entitlementTenantId} onChange={(event) => setEntitlementTenantId(event.target.value)}>
                  {data.internalTenants.map((tenant) => {
                    const tenantId = getString(tenant, ['tenant_id', 'id'], '');
                    return <option key={tenantId} value={tenantId}>{getString(tenant, ['name', 'tenant_id'], tenantId)}</option>;
                  })}
                </select>
              </label>
              {effectiveEntitlements ? (
                <div className="kv-list">
                  {entitlementFeatures.map((feature) => (
                    <div key={feature}>
                      <span>{feature}</span>
                      <strong>{effectiveEntitlements[feature] === true ? 'enabled' : 'disabled'}</strong>
                    </div>
                  ))}
                </div>
              ) : <p className="muted">Effective entitlements load after tenant subscription is fetched.</p>}
              <form className="product-form" onSubmit={grantEntitlement}>
                <label>
                  <span>Feature</span>
                  <select name="feature" defaultValue="waf_posture">
                    {entitlementFeatures.map((feature) => <option key={feature} value={feature}>{feature}</option>)}
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
                <div className="form-actions full"><Button type="submit" disabled={busy !== '' || !entitlementTenantId}>Apply entitlement</Button></div>
              </form>
            </CardContent>
          </Card>
        </>
      )}
    </div>
  );
}
