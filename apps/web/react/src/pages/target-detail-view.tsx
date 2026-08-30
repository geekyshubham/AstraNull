import { useEffect, useState } from 'react';
import { Activity, FileCheck2, ShieldCheck, Target, TriangleAlert } from 'lucide-react';
import { populateTargetDetail } from '../lib/target-detail-api';
// @ts-ignore Plain ESM keeps truthfulness rules executable in focused node tests.
import { isSignedLoaState, isTargetRunEligible, ownershipMethodLabel, targetDisplayValue, uniqueAppliedChecks, uniqueRecentRuns, uniqueVerificationHistory } from '../lib/target-detail.mjs';
import { VerifyChip, resolveTargetVerificationProvenance } from '../lib/verify-chip';
import { buildDetailHref } from '../lib/route-params';
import type { DataItem, PortalConfig, Session } from '../lib/types';
import { formatDate } from '../lib/utils';
import { AnchorButton, Button } from '../components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../components/ui/card';
import { emptyStateFromApi, readMetaAction } from '../lib/empty-from-api';
import { DataTable, type TableColumn } from '../components/ui/table';
import { Badge, type BadgeProps } from '../components/ui/badge';
import { requestJson } from '../lib/api';
import { MetricCard } from './page-components';

type StatTone = NonNullable<BadgeProps['tone']>;

const TARGET_DETAIL_STYLES_ID = 'target-detail-view-styles';
const targetDetailStyles = `
.target-detail-view { gap: var(--space-6); }
.target-detail-view > .page-head { margin-bottom: 0; }
.target-detail-view .target-detail-identity { min-width: 0; }
.target-detail-view .target-detail-identity .page-title { overflow-wrap: anywhere; }
.target-detail-view .target-detail-id { display: inline-block; margin-top: var(--space-1); font-size: var(--text-xs); overflow-wrap: anywhere; }
.target-detail-view .target-detail-workspace { align-items: start; }
.target-detail-view .target-check-choice { display: inline-flex; min-width: 44px; min-height: 44px; align-items: center; justify-content: center; cursor: pointer; }
.target-detail-view .target-check-choice input { cursor: pointer; accent-color: var(--accent); }
.target-detail-view .target-selection-note { display: flex; align-items: center; gap: var(--space-2); flex-wrap: wrap; margin: 0 0 var(--space-4); padding: var(--space-3); border: 1px solid var(--border-soft); border-radius: var(--radius-md); color: var(--fg-2); background: color-mix(in oklab, var(--surface), var(--fg) 2%); }
.target-detail-view .target-selection-note strong { color: var(--fg); }
.target-detail-view .kv { display: flex; min-width: 0; align-items: center; gap: var(--space-2); flex-wrap: wrap; }
.target-detail-view .kv-meta { min-width: 0; max-width: 100%; overflow-wrap: anywhere; word-break: break-word; white-space: normal; }
.target-detail-view .target-history { margin-top: var(--space-5); padding-top: var(--space-5); border-top: 1px solid var(--border-soft); }
.target-detail-view .target-history-head { display: flex; align-items: baseline; justify-content: space-between; gap: var(--space-3); margin-bottom: var(--space-3); }
.target-detail-view .target-history-head h3 { margin: 0; font-size: var(--text-sm); }
.target-detail-view .history-summary { margin: var(--space-3) 0 0; color: var(--muted); font-size: var(--text-xs); }
.target-detail-view .target-eligibility-callout[data-eligible="true"] { border-color: color-mix(in oklab, var(--success), transparent 55%); background: color-mix(in oklab, var(--surface), var(--success) 7%); }
.target-detail-view .target-eligibility-callout[data-eligible="true"] .callout-icon { color: var(--success); }
@media (max-width: 760px) {
  .target-detail-view .target-history-head { align-items: flex-start; flex-direction: column; }
}
`;

function ensureTargetDetailStyles() {
  if (typeof document === 'undefined' || document.getElementById(TARGET_DETAIL_STYLES_ID)) return;
  const node = document.createElement('style');
  node.id = TARGET_DETAIL_STYLES_ID;
  node.textContent = targetDetailStyles;
  document.head.appendChild(node);
}

function verificationTone(state: string): StatTone {
  const key = state.trim().toLowerCase();
  if (['agent_verified', 'dns_verified', 'user_confirmed', 'verified'].includes(key)) return 'success';
  if (key === 'pending') return 'info';
  if (key === 'unverified') return 'warn';
  return 'muted';
}

function runOutcomeTone(value: string): StatTone {
  const key = value.trim().toLowerCase();
  if (['pass', 'passed', 'complete', 'completed', 'succeeded'].includes(key)) return 'success';
  if (['gap', 'fail', 'failed', 'error', 'cancelled'].includes(key)) return 'danger';
  if (['pending', 'planned', 'queued', 'running', 'collecting'].includes(key)) return 'info';
  return 'muted';
}

function formatTargetLabel(value: string, fallback = '—') {
  const trimmed = value.trim();
  if (!trimmed) return fallback;
  const label = trimmed.replace(/_/g, ' ');
  return label.charAt(0).toUpperCase() + label.slice(1);
}

function getString(item: DataItem | null | undefined, keys: string[], fallback = '—') {
  if (!item) return fallback;
  for (const key of keys) {
    const value = item[key];
    if (value !== undefined && value !== null && value !== '') return String(value);
  }
  return fallback;
}

function DetailEntityLink({ route, id, label }: { route: 'target-group-detail' | 'finding-detail' | 'run-detail' | 'target-detail'; id: string; label?: string }) {
  if (!id) return <strong>—</strong>;
  return <AnchorButton size="sm" variant="ghost" href={buildDetailHref(route, id)} onClick={(event) => event.stopPropagation()}>{label ?? id}</AnchorButton>;
}

function verificationEvidenceReference(item: DataItem) {
  const sourceKind = getString(item, ['source_kind'], '');
  if (sourceKind) return formatTargetLabel(sourceKind);
  const sourceRef = item.source_ref && typeof item.source_ref === 'object' && !Array.isArray(item.source_ref)
    ? item.source_ref as DataItem
    : null;
  return getString(sourceRef, ['dns_challenge_id', 'agent_observation_id', 'agent_id', 'loa_id'], 'Not reported');
}

export function TargetDetailView({
  entityId,
  config,
  session,
  onRefresh
}: {
  entityId: string;
  config: PortalConfig;
  session: Session;
  onRefresh: () => Promise<void>;
}) {
  ensureTargetDetailStyles();

  const [detail, setDetail] = useState<Awaited<ReturnType<typeof populateTargetDetail>> | null>(null);
  const [busy, setBusy] = useState('');
  const [error, setError] = useState('');
  const [selectedRunCheckId, setSelectedRunCheckId] = useState('');

  useEffect(() => {
    let cancelled = false;
    setSelectedRunCheckId('');
    setDetail((current) => ({ ...(current ?? {
      target: null,
      verification: null,
      waf_posture: null,
      checks_applied: [],
      runs_recent: [],
      findings: [],
      loa: null,
      counts: null,
      loading: true
    }), loading: true }));
    populateTargetDetail(config, session, entityId).then((payload) => {
      if (!cancelled) setDetail(payload);
    });
    return () => { cancelled = true; };
  }, [config, session, entityId]);

  const target = detail?.target ?? null;
  const verification = detail?.verification ?? null;
  const wafPosture = detail?.waf_posture ?? null;
  const eligibility = getString(target, ['eligibility'], 'unknown');
  const verificationState = getString(verification, ['state'], getString(target, ['verification_state'], 'unverified'));
  const targetEligible = isTargetRunEligible(eligibility, verificationState);
  const eligibilityDisplay = targetEligible ? 'Eligible' : 'Locked';
  const provenance = resolveTargetVerificationProvenance(target, verification);
  const kind = getString(target, ['kind'], 'unknown');
  const checksApplied = uniqueAppliedChecks(detail?.checks_applied) as DataItem[];
  const runsRecent = uniqueRecentRuns(detail?.runs_recent) as DataItem[];
  const rawVerificationHistory = Array.isArray(verification?.history) ? verification.history : [];
  const verificationHistory = uniqueVerificationHistory(rawVerificationHistory) as DataItem[];
  const effectiveSelectedRunCheckId = checksApplied.some(
    (check) => getString(check, ['check_id', 'id'], '') === selectedRunCheckId
  ) ? selectedRunCheckId : '';
  const selectedRunCheck = checksApplied.find(
    (check) => getString(check, ['check_id', 'id'], '') === effectiveSelectedRunCheckId
  ) ?? null;
  const canRun = targetEligible && Boolean(effectiveSelectedRunCheckId);
  // Do not render a posture panel unless the hydrator returned a real linked asset.
  const showWaf = Boolean(wafPosture);

  async function runBoundedChecks() {
    if (!targetEligible || !target) {
      setError('This target is not explicitly eligible for bounded validation.');
      return;
    }
    if (!effectiveSelectedRunCheckId || !selectedRunCheck) {
      setError('Select a bound check before starting a bounded run.');
      return;
    }
    setBusy('run-checks');
    setError('');
    try {
      const targetGroupId = getString(target, ['target_group_id'], '');
      await requestJson(config, session, '/v1/test-runs', {
        method: 'POST',
        body: { target_group_id: targetGroupId, target_id: entityId, check_id: effectiveSelectedRunCheckId }
      });
      await onRefresh();
      const refreshed = await populateTargetDetail(config, session, entityId);
      setDetail(refreshed);
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Failed to start test run.';
      setError(message);
    } finally {
      setBusy('');
    }
  }

  // Header renders in every state (loading / empty / loaded) so the h1 target id is always present.
  function renderHeader() {
    const targetGroupId = getString(target, ['target_group_id'], '');
    const hasTarget = Boolean(target);
    return (
      <div className="page-head">
        <div className="target-detail-identity">
          <p className="eyebrow">Declared scope</p>
          <h1 className="page-title mono">{hasTarget ? targetDisplayValue(target) : entityId}</h1>
          <p className="muted">{hasTarget ? `${formatTargetLabel(kind)} target` : 'Per-target validation surface.'}</p>
          {hasTarget ? <span className="target-detail-id mono muted">{entityId}</span> : null}
          {hasTarget ? (
            <div className="detail-status-line">
              <VerifyChip state={verificationState} provenance={provenance} />
              <span className="detail-status-sep" aria-hidden="true">·</span>
              <Badge tone={targetEligible ? 'success' : 'warn'} title={`Reported eligibility ${eligibility}; ownership ${verificationState}`}>{eligibilityDisplay}</Badge>
            </div>
          ) : null}
        </div>
        <div className="row-actions">
          {targetGroupId ? (
            <AnchorButton size="sm" variant="secondary" href={buildDetailHref('target-group-detail', targetGroupId)}>← Target group</AnchorButton>
          ) : null}
          {hasTarget ? (
            <Button
              size="sm"
              className={canRun ? undefined : 'is-locked'}
              disabled={!canRun || busy !== ''}
              title={!targetEligible ? 'Target eligibility and ownership must be explicitly affirmative' : effectiveSelectedRunCheckId ? `Run selected check ${effectiveSelectedRunCheckId}` : 'Select a bound check below'}
              loading={busy === 'run-checks'}
              onClick={() => void runBoundedChecks()}
            >
              Run selected check
            </Button>
          ) : null}
        </div>
      </div>
    );
  }

  if (!detail || detail.loading) {
    return (
      <div className="content target-detail-view">
        {renderHeader()}
        <div className="stack" aria-busy="true" aria-live="polite">
          <div className="skeleton skeleton-row" />
          <div className="skeleton skeleton-row" />
          <div className="skeleton skeleton-row" />
        </div>
      </div>
    );
  }

  if (!target) {
    const emptyMeta = detail.meta && typeof detail.meta === 'object'
      ? detail.meta as DataItem
      : detail.error
        ? { empty_reason: detail.error }
        : null;
    return (
      <div className="content target-detail-view">
        {renderHeader()}
        {emptyStateFromApi({
          icon: Target,
          meta: emptyMeta,
          actionHref: readMetaAction(emptyMeta, 'empty_action_href'),
          actionLabel: readMetaAction(emptyMeta, 'empty_action_label')
        })}
      </div>
    );
  }

  const runColumns: TableColumn<DataItem>[] = [
    { key: 'run', label: 'Run', render: (item) => <DetailEntityLink route="run-detail" id={getString(item, ['run_id', 'id'], '')} /> },
    { key: 'binding', label: 'Rule / policy ref', render: (item) => <span className="mono">{getString(item, ['check_id', 'policy_id', 'test_policy_id'], 'Not reported')}</span> },
    { key: 'outcome', label: 'Recorded outcome / status', render: (item) => {
      const value = getString(item, ['verdict', 'status'], 'unknown');
      return <Badge tone={runOutcomeTone(value)} title={`Value ${value} from target-detail runs API; it may be a verdict or lifecycle status`}>{formatTargetLabel(value)}</Badge>;
    } },
    { key: 'started', label: 'Started', render: (item) => formatDate(item.started_at ?? item.created_at) }
  ];

  const findingColumns: TableColumn<DataItem>[] = [
    { key: 'severity', label: 'Severity', render: (item) => getString(item, ['severity'], 'unknown') },
    { key: 'id', label: 'Finding', render: (item) => <DetailEntityLink route="finding-detail" id={getString(item, ['id'], '')} label={getString(item, ['title'], getString(item, ['id']))} /> },
    { key: 'target', label: 'Target', render: (item) => <DetailEntityLink route="target-detail" id={getString(item, ['target_id'], entityId)} label={getString(item, ['target_value', 'target'], getString(target, ['value'], getString(item, ['target_id'], entityId)))} /> },
    { key: 'state', label: 'State', render: (item) => getString(item, ['state', 'status'], 'open') },
    { key: 'opened', label: 'Opened', render: (item) => formatDate(item.opened_at ?? item.created_at) },
    { key: 'owner', label: 'Owner', render: (item) => getString(item, ['owner_group', 'assignee'], 'unassigned') }
  ];

  const checkColumns: TableColumn<DataItem>[] = [
    { key: 'select', label: 'Select', render: (item) => {
      const checkId = getString(item, ['check_id', 'id'], '');
      return (
        <label className="target-check-choice">
          <input
            type="radio"
            name="target-run-check"
            value={checkId}
            checked={effectiveSelectedRunCheckId === checkId}
            disabled={!checkId}
            onChange={() => setSelectedRunCheckId(checkId)}
            aria-label={`Select check ${checkId} for this target's bounded run`}
          />
        </label>
      );
    } },
    { key: 'check', label: 'Bound check', render: (item) => <span className="mono">{getString(item, ['check_id', 'id'], 'Not reported')}</span> },
    { key: 'scope', label: 'Scope', render: () => <span className="muted small">Target-group binding reported by target-detail API</span> }
  ];

  const verificationHistoryColumns: TableColumn<DataItem>[] = [
    { key: 'state', label: 'Recorded state', render: (item) => <VerifyChip state={getString(item, ['state'], 'unknown')} provenance={`Recorded target verification transition ${getString(item, ['state'], 'unknown')}`} /> },
    { key: 'transitioned', label: 'Transitioned', render: (item) => item.transitioned_at ? formatDate(item.transitioned_at) : <span className="muted">Not reported</span> },
    { key: 'evidence', label: 'Evidence reference', render: (item) => <span className="mono">{verificationEvidenceReference(item)}</span> }
  ];

  const loa = detail.loa;
  const loaState = getString(loa, ['state', 'status'], '');
  const loaSigned = isSignedLoaState(loaState);
  const loaCustody = getString(loa, ['custody_digest_sha256', 'custody_digest', 'digest'], '');
  const loaSigner = getString(loa, ['signer_name', 'signed_by'], '');
  const loaSignedAt = loa?.signed_at ?? loa?.updated_at;
  const agentBinding = target.agent_binding && typeof target.agent_binding === 'object' && !Array.isArray(target.agent_binding)
    ? target.agent_binding as DataItem
    : null;
  const agentBindingId = getString(agentBinding, ['agent_id'], 'none');
  const agentBindingAt = agentBinding?.bound_at ?? agentBinding?.last_heartbeat_at ?? agentBinding?.updated_at;
  const ownershipMethod = ownershipMethodLabel(verification);
  const expectedBehavior = getString(target, ['expected_behavior', 'expected'], '—');
  const reportedEligibilityReason = getString(target, ['eligibility_reason'], '');
  const eligibilityReason = reportedEligibilityReason
    ? `Target API reason: ${formatTargetLabel(reportedEligibilityReason)}.`
    : targetEligible
      ? 'The target API explicitly reports eligible ownership state.'
      : 'The target API did not report an explicitly eligible ownership state, so validation remains locked.';

  return (
    <div className="content target-detail-view">
      {error ? <div className="form-banner error" role="alert">{error}</div> : null}
      {renderHeader()}

      <div className="metric-grid four">
        <MetricCard label="Kind" value={kind} sub="Declared target type" icon={Target} tone="info" />
        <MetricCard label="Expected behavior" value={formatTargetLabel(getString(target, ['expected_behavior', 'expected'], '—'))} sub="Declared expectation" icon={Activity} tone="muted" />
        <MetricCard label="Verification" value={formatTargetLabel(verificationState)} sub="Ownership signal from target API" icon={ShieldCheck} tone={verificationTone(verificationState)} />
        <MetricCard label="Eligibility" value={eligibilityDisplay} sub={targetEligible ? 'Explicitly eligible for checks' : 'Validation locked (fail closed)'} icon={FileCheck2} tone={targetEligible ? 'success' : 'warn'} />
      </div>

      <Card>
        <CardHeader><CardTitle>Ownership + eligibility</CardTitle><CardDescription>{ownershipMethod}</CardDescription></CardHeader>
        <CardContent>
          <div className="stack-tight">
            <div className="table-wrap" tabIndex={0} role="region" aria-label="Ownership and eligibility, scrollable">
              <table className="data-table">
                <tbody>
                  <tr><td className="muted">Ownership method</td><td><div className="kv"><span className="mono">{ownershipMethod}</span></div></td></tr>
                  <tr><td className="muted">Ownership status</td><td><div className="kv"><VerifyChip state={verificationState} provenance={provenance} /></div></td></tr>
                  <tr><td className="muted">Target group</td><td><div className="kv"><span className="mono">{getString(target, ['target_group_id'], '—')}</span></div></td></tr>
                  <tr><td className="muted">Environment</td><td><div className="kv"><span className="mono">{getString(target, ['environment_id'], 'Not reported')}</span></div></td></tr>
                  <tr><td className="muted">Expected behavior</td><td><div className="kv"><span className="mono">{expectedBehavior}</span></div></td></tr>
                  {agentBinding ? (
                    <tr><td className="muted">Agent binding</td><td><div className="kv"><span className="mono">{agentBindingId}</span>{agentBindingAt ? <span className="kv-meta">{formatDate(agentBindingAt)}</span> : null}</div></td></tr>
                  ) : null}
                  <tr><td className="muted">Group LOA</td><td><div className="kv"><Badge tone={loaSigned ? 'success' : loaState ? 'warn' : 'muted'} title="LOA state from target group API">{loaState ? formatTargetLabel(loaState) : 'Not reported'}</Badge>{loaCustody ? <span className="kv-meta">{loaCustody}</span> : null}</div></td></tr>
                  {loaSigner ? (
                    <tr><td className="muted">LOA signer</td><td><div className="kv"><span>{loaSigner}</span>{loaSignedAt ? <span className="kv-meta">{formatDate(loaSignedAt)}</span> : null}</div></td></tr>
                  ) : null}
                </tbody>
              </table>
            </div>
            {verificationHistory.length > 0 ? (
              <div className="target-history">
                <div className="target-history-head">
                  <h3>Recorded verification transitions</h3>
                  <span className="muted small">Exact duplicate API rows removed · oldest to newest</span>
                </div>
                <DataTable
                  columns={verificationHistoryColumns}
                  items={verificationHistory}
                  getRowId={(item, index) => `${getString(item, ['state'], 'unknown')}-${getString(item, ['transitioned_at'], String(index))}-${index}`}
                  empty={<span className="muted">No verification transitions reported.</span>}
                />
              </div>
            ) : null}
            <div className="callout target-eligibility-callout" data-eligible={String(targetEligible)}>
              <span className="callout-icon" aria-hidden="true"><ShieldCheck size={18} /></span>
              <div className="callout-body">
                <p className="callout-title"><Badge tone={targetEligible ? 'success' : 'warn'}>{eligibilityDisplay}</Badge> for validation</p>
                <p className="callout-desc">{eligibilityReason}</p>
              </div>
            </div>
          </div>
        </CardContent>
      </Card>

      {showWaf ? (
        <Card>
          <CardHeader><CardTitle>WAF posture</CardTitle><CardDescription>Linked per-target WAF asset returned by the target-detail API.</CardDescription></CardHeader>
          <CardContent>
            <div className="kpi-row">
              <div className="kpi-cell"><div className="kpi-label">Posture</div><div className="kpi-value">{getString(wafPosture, ['posture', 'status'], '—')}</div></div>
              <div className="kpi-cell"><div className="kpi-label">Drift</div><div className="kpi-value">{getString(wafPosture, ['drift_reason'], 'none')}</div></div>
              <div className="kpi-cell"><div className="kpi-label">Validation</div><div className="kpi-value">{getString(wafPosture?.validation as DataItem | undefined, ['verdict'], '—')}</div></div>
              <div className="kpi-cell"><div className="kpi-label">Connector</div><div className="kpi-value">{getString(wafPosture?.connector as DataItem | undefined, ['state'], '—')}</div></div>
              <div className="kpi-cell"><div className="kpi-label">Fingerprint</div><div className="kpi-value mono" title={getString(wafPosture?.fingerprint as DataItem | undefined, ['signature'], '—')}>{getString(wafPosture?.fingerprint as DataItem | undefined, ['signature'], '—')}</div></div>
              <div className="kpi-cell"><div className="kpi-label">Marker rules</div><div className="kpi-value">{String(wafPosture?.marker_rules ?? '—')}</div></div>
              <div className="kpi-cell"><div className="kpi-label">Origin bypass</div><div className="kpi-value">{getString(wafPosture?.origin_bypass as DataItem | undefined, ['state'], '—')}</div></div>
            </div>
            <p className="muted">{getString(wafPosture, ['notes'], getString(wafPosture, ['summary'], 'No WAF notes returned.'))}</p>
            <pre className="codeblock" tabIndex={0} role="region" aria-label="WAF posture technical details">{JSON.stringify({
              asset_id: getString(wafPosture, ['asset_id'], ''),
              vendor: getString(wafPosture, ['vendor'], ''),
              target: getString(target, ['value'], ''),
              target_group: getString(target, ['target_group_id'], ''),
              posture: getString(wafPosture, ['posture'], ''),
              drift_reason: getString(wafPosture, ['drift_reason'], ''),
              validation: wafPosture?.validation ?? null,
              connector: wafPosture?.connector ?? null
            }, null, 2)}</pre>
          </CardContent>
        </Card>
      ) : null}

      <div className="dash-grid target-detail-workspace">
        <Card>
          <CardHeader>
            <div><CardTitle>Bound checks</CardTitle><CardDescription>Select the exact check used by Run selected check. Bindings are not presented as target run history.</CardDescription></div>
            <Badge tone={effectiveSelectedRunCheckId ? 'success' : 'warn'}>{effectiveSelectedRunCheckId ? 'Selected' : 'Selection required'}</Badge>
          </CardHeader>
          <CardContent>
            {checksApplied.length > 0 ? (
              <div className="target-selection-note" role="note">
                <span>Selected check:</span>
                <strong className="mono">{effectiveSelectedRunCheckId || 'None'}</strong>
              </div>
            ) : null}
            <DataTable columns={checkColumns} items={checksApplied} empty={emptyStateFromApi({ icon: FileCheck2, meta: detail.sectionMeta?.checks })} />
          </CardContent>
        </Card>
        <Card>
          <CardHeader><div><CardTitle>Recent runs</CardTitle><CardDescription>Canonical target-scoped rows from the hydrator; duplicate run IDs are shown once.</CardDescription></div></CardHeader>
          <CardContent>
            <DataTable columns={runColumns} items={runsRecent} empty={emptyStateFromApi({ icon: Activity, meta: detail.sectionMeta?.runs, actionHref: '#runs', actionLabel: 'Open test runs' })} />
            {runsRecent.length > 0 ? <p className="history-summary">Showing {runsRecent.length} recent unique run{runsRecent.length === 1 ? '' : 's'} returned by the target-detail API.</p> : null}
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader><CardTitle>Findings on this target</CardTitle></CardHeader>
        <CardContent>
          <DataTable columns={findingColumns} items={detail.findings} empty={emptyStateFromApi({ icon: TriangleAlert, meta: detail.sectionMeta?.findings, actionHref: '#findings', actionLabel: 'Open findings' })} />
        </CardContent>
      </Card>
    </div>
  );
}
