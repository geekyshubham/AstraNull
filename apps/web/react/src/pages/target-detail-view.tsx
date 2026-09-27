import { useEffect, useState } from 'react';
import { Activity, Check, Cloud, FileCheck2, Network, Server, ShieldCheck, Target, TriangleAlert } from 'lucide-react';
import { populateTargetDetail } from '../lib/target-detail-api';
import { hasEvidenceBackedVerdict, publishedRunVerdict } from '../lib/environments';
import { findingStatus } from '../lib/finding-lifecycle.mjs';
// @ts-ignore Plain ESM keeps truthfulness rules executable in focused node tests.
import { edgeDetectionReasonExplanation, edgeFamilyProviderSummary, isSignedLoaState, isTargetRunEligible, ownershipMethodLabel, targetDeclarationProvenanceLabel, targetDisplayValue, uniqueAppliedChecks, uniqueRecentRuns, uniqueVerificationHistory } from '../lib/target-detail.mjs';
import { VerifyChip, resolveTargetVerificationProvenance } from '../lib/verify-chip';
import { buildDetailHref } from '../lib/route-params';
import type { DataItem, PortalConfig, Session } from '../lib/types';
import { formatDate, formatSeverityLabel } from '../lib/utils';
import { AnchorButton, Button } from '../components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../components/ui/card';
import { EvidenceGuide } from '../components/ui/evidence-guide';
import { emptyStateFromApi, readMetaAction } from '../lib/empty-from-api';
import { DataTable, type TableColumn } from '../components/ui/table';
import { Badge, type BadgeProps } from '../components/ui/badge';
import { requestJson } from '../lib/api';
import { canStartRun } from '../lib/run-permissions.mjs';
import { MetricCard } from './page-components';
// @ts-ignore Plain ESM keeps evidence-conservative labels directly testable with node:test.
import { evidenceModePresentation, evidenceTierInfo, plainCheckName, plainCodeLabel, plainFindingTitle, plainProtectionLabel, plainVerdictLabel, plainVerificationLabel } from '../lib/plain-language.mjs';

type StatTone = NonNullable<BadgeProps['tone']>;

const TARGET_DETAIL_STYLES_ID = 'target-detail-view-styles';
const targetDetailStyles = `
.target-detail-view { gap: var(--space-6); }
.target-detail-view > .page-head { margin-bottom: 0; }
.target-detail-view .target-detail-identity { min-width: 0; }
.target-detail-view .target-detail-identity .page-title { overflow-wrap: anywhere; }
.target-detail-view .target-detail-id { display: inline-block; margin-top: var(--space-1); font-size: var(--text-xs); overflow-wrap: anywhere; }
.target-detail-view .target-detail-workspace { display: flex; flex-direction: column; align-items: stretch; gap: var(--space-6); }
.target-detail-view .target-check-choice { display: inline-flex; min-width: 44px; min-height: 44px; align-items: center; justify-content: center; cursor: pointer; }
.target-detail-view .target-check-choice input { cursor: pointer; accent-color: var(--accent); }
.target-detail-view .target-selection-note { display: flex; align-items: center; gap: var(--space-2); flex-wrap: wrap; margin: 0 0 var(--space-4); padding: var(--space-3); border: 1px solid var(--border-soft); border-radius: var(--radius-md); color: var(--fg-2); background: color-mix(in oklab, var(--surface), var(--fg) 2%); }
.target-detail-view .target-selection-note strong { color: var(--fg); }
.target-detail-view .kv { display: flex; min-width: 0; align-items: center; gap: var(--space-2); flex-wrap: wrap; }
.target-detail-view .kv-meta { min-width: 0; max-width: 100%; overflow-wrap: anywhere; word-break: break-word; white-space: normal; }
.target-detail-view .target-verification-card .verify-ladder { margin-bottom: 0; }
.target-detail-view .target-verification-card .target-eligibility-callout { margin-top: var(--space-4); }
.target-detail-view .target-facts-card .data-table td:first-child { width: 32%; }
.target-detail-view .target-facts-card .mono { min-width: 0; overflow-wrap: anywhere; word-break: break-word; white-space: normal; }
.target-detail-view .target-history { margin-top: var(--space-5); padding-top: var(--space-5); border-top: 1px solid var(--border-soft); }
.target-detail-view .target-history-head { display: flex; align-items: baseline; justify-content: space-between; gap: var(--space-3); margin-bottom: var(--space-3); }
.target-detail-view .target-history-head h3 { margin: 0; font-size: var(--text-sm); }
.target-detail-view .history-summary { margin: var(--space-3) 0 0; color: var(--muted); font-size: var(--text-xs); }
.target-detail-view .target-eligibility-callout[data-eligible="true"] { border-color: color-mix(in oklab, var(--success), transparent 55%); background: color-mix(in oklab, var(--surface), var(--success) 7%); }
.target-detail-view .target-eligibility-callout[data-eligible="true"] .callout-icon { color: var(--success); }
.target-detail-view .edge-family-grid { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: var(--space-3); margin: var(--space-4) 0; }
.target-detail-view .edge-family-card { min-width: 0; padding: var(--space-3); border: 1px solid var(--border-soft); border-radius: var(--radius-md); background: var(--surface); }
.target-detail-view .edge-family-card-head { display: flex; align-items: center; justify-content: space-between; gap: var(--space-2); margin-bottom: var(--space-2); }
.target-detail-view .edge-family-card-head strong { font-size: var(--text-sm); }
.target-detail-view .edge-family-card dl { display: grid; grid-template-columns: max-content minmax(0, 1fr); gap: var(--space-1) var(--space-3); margin: 0; }
.target-detail-view .edge-family-card dt { color: var(--muted); font-size: var(--text-xs); }
.target-detail-view .edge-family-card dd { min-width: 0; margin: 0; color: var(--fg); font-size: var(--text-xs); overflow-wrap: anywhere; }
.target-detail-view .edge-evidence-block { margin-top: var(--space-4); padding-top: var(--space-4); border-top: 1px solid var(--border-soft); }
.target-detail-view .edge-evidence-block h3 { margin: 0 0 var(--space-2); font-size: var(--text-sm); }
.target-detail-view .edge-chip-row { display: flex; align-items: center; gap: var(--space-2); flex-wrap: wrap; }
.target-detail-view .edge-chain { margin: var(--space-2) 0 0; color: var(--fg-2); font-size: var(--text-xs); overflow-wrap: anywhere; }
.target-detail-view .edge-chain .edge-chain-label { color: var(--muted); margin-right: var(--space-2); }
.target-detail-view .target-protection-lede { max-width: 78ch; margin: 0; color: var(--fg); font-size: var(--text-lg); line-height: 1.45; text-wrap: pretty; }
.target-detail-view .target-protection-source { margin: var(--space-2) 0 0; color: var(--fg-2); font-size: var(--text-xs); }
.target-detail-view .target-protection-grid { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 1px; margin-top: var(--space-5); overflow: hidden; border: 1px solid var(--border); border-radius: var(--radius-md); background: var(--border-soft); }
.target-detail-view .target-protection-layer { display: flex; min-width: 0; flex-direction: column; gap: var(--space-3); padding: var(--space-4); background: var(--surface); }
.target-detail-view .target-protection-layer-head { display: flex; align-items: center; gap: var(--space-2); color: var(--fg-2); }
.target-detail-view .target-protection-layer-head strong { color: var(--fg); font-size: var(--text-sm); }
.target-detail-view .target-protection-layer-value { display: flex; align-items: center; gap: var(--space-2); flex-wrap: wrap; }
.target-detail-view .target-protection-layer-value > strong { color: var(--fg); font-size: var(--text-sm); line-height: 1.4; }
.target-detail-view .target-protection-layer p { margin: 0; color: var(--fg-2); font-size: var(--text-xs); line-height: 1.5; }
.target-detail-view .waf-effectiveness { display: grid; grid-template-columns: minmax(180px, 0.75fr) minmax(0, 1.5fr); gap: var(--space-5); align-items: center; margin-top: var(--space-5); padding: var(--space-4); border: 1px solid var(--border); border-radius: var(--radius-md); }
.target-detail-view .waf-effectiveness-copy { display: flex; flex-direction: column; gap: var(--space-1); }
.target-detail-view .waf-effectiveness-copy h3 { margin: 0; color: var(--fg); font-size: var(--text-sm); }
.target-detail-view .waf-effectiveness-copy p { margin: 0; color: var(--fg-2); font-size: var(--text-xs); line-height: 1.5; }
.target-detail-view .effectiveness-scale { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: var(--space-2); }
.target-detail-view .effectiveness-step { min-width: 0; padding: var(--space-2) var(--space-3); border: 1px solid var(--border-soft); border-radius: var(--radius-sm); color: var(--fg-2); font-size: var(--text-xs); text-align: center; }
.target-detail-view .effectiveness-step[aria-current="true"] { border-color: var(--border-strong); background: var(--surface-sunk); color: var(--fg); font-weight: 700; }
.target-detail-view .evidence-mode-cell { display: flex; max-width: 28rem; flex-direction: column; align-items: flex-start; gap: var(--space-1); }
.target-detail-view .evidence-mode-cell > span:last-child { color: var(--fg-2); font-size: var(--text-xs); line-height: 1.4; }
@media (max-width: 1100px) {
  .target-detail-view .target-protection-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
}
@media (max-width: 760px) {
  .target-detail-view .target-history-head { align-items: flex-start; flex-direction: column; }
  .target-detail-view .edge-family-grid { grid-template-columns: minmax(0, 1fr); }
  .target-detail-view .target-protection-grid,
  .target-detail-view .waf-effectiveness { grid-template-columns: minmax(0, 1fr); }
  .target-detail-view .effectiveness-scale { grid-template-columns: minmax(0, 1fr); }
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
  if (['agent_verified', 'dns_verified', 'provider_verified', 'user_confirmed', 'verified'].includes(key)) return 'success';
  if (key === 'pending') return 'info';
  if (key === 'unverified') return 'warn';
  return 'muted';
}

function runOutcomeTone(value: string): StatTone {
  const key = value.trim().toLowerCase();
  if (['pass', 'passed', 'protected', 'complete', 'completed', 'succeeded'].includes(key)) return 'success';
  if (['gap', 'fail', 'failed', 'bypassable', 'penetrated', 'unprotected', 'error', 'cancelled'].includes(key)) return 'danger';
  if (['pending', 'planned', 'queued', 'running', 'collecting'].includes(key)) return 'info';
  return 'muted';
}

function formatTargetLabel(value: string, fallback = '—') {
  const trimmed = value.trim();
  if (!trimmed) return fallback;
  const friendly: Record<string, string> = {
    fqdn: 'Domain name',
    cloud_baseline: 'Protected path baseline',
    must_block_before_origin: 'Block before the origin server',
  };
  const key = trimmed.toLowerCase();
  if (friendly[key]) return friendly[key];
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

function asDataItem(value: unknown): DataItem | null {
  return value && typeof value === 'object' && !Array.isArray(value) ? value as DataItem : null;
}

function getOptionalNumber(item: DataItem | null | undefined, keys: string[]) {
  if (!item) return null;
  for (const key of keys) {
    const value = item[key];
    if (typeof value === 'number' && Number.isFinite(value)) return value;
  }
  return null;
}

function dataItemList(value: unknown, maxItems = 8): DataItem[] {
  if (!Array.isArray(value)) return [];
  return value.map(asDataItem).filter((entry): entry is DataItem => Boolean(entry)).slice(0, maxItems);
}

function stringList(value: unknown, maxItems = 8) {
  if (!Array.isArray(value)) return [];
  const items: string[] = [];
  for (const entry of value) {
    const text = typeof entry === 'string' ? entry.trim() : '';
    if (text && !items.includes(text)) items.push(text);
    if (items.length >= maxItems) break;
  }
  return items;
}

function edgeStatusTone(status: string): StatTone {
  const key = status.trim().toLowerCase();
  if (key === 'detected') return 'success';
  if (key === 'not_detected') return 'muted';
  if (key === 'error') return 'danger';
  if (key === 'inconclusive') return 'warn';
  if (key === 'pending') return 'info';
  return 'muted';
}

/** Percentage rendering for the 0..1 detection confidence; empty when the API reported none. */
function edgeConfidenceLabel(value: unknown) {
  if (value === null || value === undefined || value === '') return '';
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) return '';
  return `${Math.round(Math.max(0, Math.min(1, parsed)) * 100)}%`;
}

function EdgeFamilyProviders({ family, providers }: { family: DataItem | null; providers: string[] }) {
  const summary = edgeFamilyProviderSummary(getString(family, ['provider'], ''), providers) as { label: string; value: string };
  return <><dt>{summary.label}</dt><dd>{summary.value}</dd></>;
}

function EvidenceModeCell({ item, check }: { item: DataItem; check?: DataItem | null }) {
  const mode = evidenceModePresentation(item, check);
  return (
    <span className="evidence-mode-cell">
      <Badge tone={mode.tone} title={`${mode.detail}${mode.code ? ` Technical tier ${mode.code}.` : ''}`}>
        {mode.label}{mode.code ? ` · ${mode.code}` : ''}
      </Badge>
      <span>{mode.detail}</span>
    </span>
  );
}

function protectionStateTone(value: string): StatTone {
  const key = value.trim().toLowerCase();
  if (['protected', 'pass', 'passed', 'detected', 'not_exposed', 'active'].includes(key)) return 'success';
  if (['underprotected', 'unprotected', 'fail', 'failed', 'exposed', 'bypassable', 'penetrated', 'error'].includes(key)) return 'danger';
  if (['edge_protected', 'inconclusive', 'suspected', 'pending', 'degraded'].includes(key)) return 'warn';
  return 'muted';
}

function ProtectionLayer({
  icon: Icon,
  label,
  value,
  detail,
  technicalState,
  tone,
}: {
  icon: typeof Activity;
  label: string;
  value: string;
  detail: string;
  technicalState: string;
  tone: StatTone;
}) {
  return (
    <section className="target-protection-layer" aria-label={`${label}: ${value}`}>
      <div className="target-protection-layer-head"><Icon size={16} aria-hidden="true" /><strong>{label}</strong></div>
      <div className="target-protection-layer-value">
        <Badge tone={tone} title={`${detail}${technicalState ? ` Recorded state: ${plainCodeLabel(technicalState)}.` : ''}`}>{value}</Badge>
      </div>
      <p>{detail}</p>
    </section>
  );
}

/** Target-detail runs carry the verdict record's evidence ids beside the verdict text. */
function recentRunVerdict(run: DataItem) {
  const normalizedRun = {
    ...run,
    id: getString(run, ['run_id', 'id'], ''),
    evidence_ids: run.evidence_ids,
  };
  return hasEvidenceBackedVerdict(normalizedRun, []) ? publishedRunVerdict(normalizedRun) : '';
}

function boundCheckScope(check: DataItem) {
  const policyId = getString(check, ['policy_id'], '');
  if (!policyId) return 'Binding source not reported';
  const scope = getString(check, ['binding_scope'], '') === 'target' ? 'Target policy' : 'Target-group policy';
  const state = getString(check, ['policy_state'], '');
  return `${scope}${state && state !== 'active' ? ` · ${formatTargetLabel(state).toLowerCase()}` : ''}`;
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

type TargetVerificationLadderStep = {
  id: string;
  label: string;
  done: boolean;
  meta: string;
};

/** Build the visual ladder only from the current state and exact transition rows the API returned. */
function buildTargetVerificationLadder(
  target: DataItem,
  verification: DataItem | null,
  history: DataItem[],
): TargetVerificationLadderStep[] {
  const currentState = getString(verification, ['state'], getString(target, ['verification_state'], 'unverified')).trim().toLowerCase();
  const historyStates = new Set(history.map((item) => getString(item, ['state'], '').trim().toLowerCase()).filter(Boolean));
  const hasState = (states: string[]) => states.includes(currentState) || states.some((state) => historyStates.has(state));
  const transitionMeta = (states: string[], fallback: string) => {
    const transition = [...history].reverse().find((item) => states.includes(getString(item, ['state'], '').trim().toLowerCase()));
    return transition?.transitioned_at ? `${fallback} · ${formatDate(transition.transitioned_at)}` : fallback;
  };
  const ownershipStates = ['dns_verified', 'provider_verified', 'agent_verified', 'user_confirmed', 'verified'];
  const ownershipDone = hasState(ownershipStates);
  const agentDone = hasState(['agent_verified']);
  const userDone = hasState(['user_confirmed']);
  const method = ownershipMethodLabel(verification);

  return [
    {
      id: 'declared',
      label: 'Target declared',
      done: true,
      meta: plainCheckName(targetDeclarationProvenanceLabel(target)),
    },
    {
      id: 'ownership',
      label: 'Ownership proven',
      done: ownershipDone,
      meta: ownershipDone
        ? transitionMeta(ownershipStates, method)
        : 'No accepted DNS, provider, agent, or user proof is recorded.',
    },
    {
      id: 'agent',
      label: 'Observed from inside',
      done: agentDone,
      meta: agentDone
        ? transitionMeta(['agent_verified'], 'Agent verification recorded')
        : 'No agent verification transition is asserted.',
    },
    {
      id: 'confirmed',
      label: 'Owner confirmed',
      done: userDone,
      meta: userDone
        ? transitionMeta(['user_confirmed'], 'Authorized user confirmation recorded')
        : 'No authorized user confirmation is recorded.',
    },
  ];
}

export function TargetDetailView({
  entityId,
  config,
  session,
  checks,
  onRefresh
}: {
  entityId: string;
  config: PortalConfig;
  session: Session;
  checks: DataItem[];
  onRefresh: () => Promise<void>;
}) {
  ensureTargetDetailStyles();

  const [detail, setDetail] = useState<Awaited<ReturnType<typeof populateTargetDetail>> | null>(null);
  const [busy, setBusy] = useState('');
  const [error, setError] = useState('');
  const [startedRunId, setStartedRunId] = useState('');
  const [selectedRunCheckId, setSelectedRunCheckId] = useState('');
  const [edgeRequestResult, setEdgeRequestResult] = useState<DataItem | null>(null);

  useEffect(() => {
    let cancelled = false;
    setSelectedRunCheckId('');
    setDetail((current) => ({ ...(current ?? {
      target: null,
      verification: null,
      waf_posture: null,
      edge_detection: null,
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

  const edgeRequest = asDataItem(detail?.edge_detection_request);
  const edgeRequestId = getString(edgeRequest, ['test_run_id'], '');
  const durableEdgeRunId = getString(asDataItem(detail?.edge_detection), ['test_run_id'], '');
  const showEdgeRequest = Boolean(edgeRequestId) && edgeRequestId !== durableEdgeRunId;

  useEffect(() => {
    setEdgeRequestResult(null);
    if (!showEdgeRequest) return undefined;
    let cancelled = false;
    requestJson(config, session, `/v1/waf/edge-detection/${encodeURIComponent(edgeRequestId)}`)
      .then((payload) => { if (!cancelled) setEdgeRequestResult(asDataItem(payload)); })
      .catch((err) => {
        if (!cancelled) setEdgeRequestResult({ status: 'unavailable', read_error: err instanceof Error ? err.message : 'Result read failed' });
      });
    return () => { cancelled = true; };
  }, [config, session, edgeRequestId, showEdgeRequest]);

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
  const checkById = new Map([...checks, ...checksApplied].map((check) => [getString(check, ['check_id', 'id'], ''), check]));
  const displayCheckName = (checkId: string) => plainCheckName(getString(checkById.get(checkId), ['name', 'title', 'check_name'], checkId || 'Unnamed check'));
  const runsRecent = uniqueRecentRuns(detail?.runs_recent) as DataItem[];
  const rawVerificationHistory = Array.isArray(verification?.history) ? verification.history : [];
  const verificationHistory = uniqueVerificationHistory(rawVerificationHistory) as DataItem[];
  const verificationLadder = target ? buildTargetVerificationLadder(target, verification, verificationHistory) : [];
  const declarationProvenance = target ? plainCheckName(targetDeclarationProvenanceLabel(target)) : 'Not reported';
  const effectiveSelectedRunCheckId = checksApplied.some(
    (check) => getString(check, ['check_id', 'id'], '') === selectedRunCheckId
  ) ? selectedRunCheckId : '';
  const selectedRunCheck = checksApplied.find(
    (check) => getString(check, ['check_id', 'id'], '') === effectiveSelectedRunCheckId
  ) ?? null;
  const canStartBoundedRun = canStartRun(session.role);
  const canRun = canStartBoundedRun && targetEligible && Boolean(effectiveSelectedRunCheckId);
  // Do not render a posture panel unless the hydrator returned a real linked asset.
  const showWaf = Boolean(wafPosture);

  async function runBoundedChecks() {
    if (!canStartBoundedRun) {
      setError('Your role can review target evidence but cannot start validation runs.');
      return;
    }
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
    setStartedRunId('');
    try {
      const targetGroupId = getString(target, ['target_group_id'], '');
      const started = await requestJson(config, session, '/v1/test-runs', {
        method: 'POST',
        body: { target_group_id: targetGroupId, target_id: entityId, check_id: effectiveSelectedRunCheckId }
      }) as { run?: { id?: unknown }; id?: unknown };
      setStartedRunId(String(started?.run?.id ?? started?.id ?? '').trim() || 'started');
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
          <p className="eyebrow">Declared target</p>
          <h1 className="page-title mono">{hasTarget ? targetDisplayValue(target) : entityId}</h1>
          <p className="muted">{hasTarget ? `${formatTargetLabel(kind)} · Expected behavior: ${formatTargetLabel(getString(target, ['expected_behavior', 'expected'], 'Not reported'))}` : 'Per-target validation surface.'}</p>
          {hasTarget ? <span className="target-detail-id mono muted">{entityId}</span> : null}
          {hasTarget ? (
            <div className="detail-status-line">
              <VerifyChip state={verificationState} provenance={provenance} label={plainVerificationLabel(verificationState)} />
              <span className="detail-status-sep" aria-hidden="true">·</span>
              <Badge tone={targetEligible ? 'success' : 'warn'} title={`Reported eligibility ${eligibility}; ownership ${verificationState}`}>{eligibilityDisplay}</Badge>
            </div>
          ) : null}
        </div>
        <div className="row-actions">
          <AnchorButton size="sm" variant="ghost" href="#targets">All targets</AnchorButton>
          {targetGroupId ? (
            <AnchorButton size="sm" variant="secondary" href={buildDetailHref('target-group-detail', targetGroupId)}>← Target group</AnchorButton>
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
    { key: 'run', label: 'Run', render: (item) => {
      const runId = getString(item, ['run_id', 'id'], '');
      const checkId = getString(item, ['check_id'], '');
      return <span className="entity-cell-stack"><DetailEntityLink route="run-detail" id={runId} label={`${displayCheckName(checkId)} · ${targetDisplayValue(target)}`} /><small className="mono">{runId}</small></span>;
    } },
    { key: 'binding', label: 'Rule / policy ref', render: (item) => { const policyId = getString(item, ['policy_id', 'test_policy_id'], ''); return <span title={policyId || undefined}>{policyId ? 'Scheduled policy' : 'Direct selection'}</span>; } },
    { key: 'status', label: 'Lifecycle', render: (item) => {
      const value = getString(item, ['status', 'run_status'], 'unknown');
      return <Badge tone={runOutcomeTone(value)} title="Recorded run lifecycle">{formatTargetLabel(value)}</Badge>;
    } },
    { key: 'verdict', label: 'Verdict', render: (item) => {
      const value = recentRunVerdict(item);
      const evidenceCount = Array.isArray(item.evidence_ids) ? item.evidence_ids.length : 0;
      return value
        ? <Badge tone={runOutcomeTone(value)} title={`Technical verdict ${value}; ${getString(item, ['verdict_id'], 'record')} cites ${evidenceCount} evidence record${evidenceCount === 1 ? '' : 's'}`}>{plainVerdictLabel(value)}</Badge>
        : <span className="muted">No evidence-backed result</span>;
    } },
    { key: 'evidence', label: 'How it was checked', render: (item) => <EvidenceModeCell item={item} check={checkById.get(getString(item, ['check_id'], ''))} /> },
    { key: 'started', label: 'Started', render: (item) => formatDate(item.started_at ?? item.created_at) }
  ];

  const findingColumns: TableColumn<DataItem>[] = [
    { key: 'severity', label: 'Severity', render: (item) => formatSeverityLabel(getString(item, ['severity'], 'unknown')) },
    { key: 'id', label: 'Finding', render: (item) => <span className="entity-cell-stack"><DetailEntityLink route="finding-detail" id={getString(item, ['id'], '')} label={plainFindingTitle(item, [target], checks)} /><small className="mono">{getString(item, ['id'], '')}</small></span> },
    { key: 'target', label: 'Target', render: (item) => <DetailEntityLink route="target-detail" id={getString(item, ['target_id'], entityId)} label={getString(item, ['target_value', 'target'], getString(target, ['value'], getString(item, ['target_id'], entityId)))} /> },
    { key: 'state', label: 'State', render: (item) => findingStatus(item) },
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
    { key: 'check', label: 'Bound check', render: (item) => { const checkId = getString(item, ['check_id', 'id'], ''); return <span className="entity-cell-stack"><strong>{displayCheckName(checkId)}</strong><small className="mono">{checkId}</small></span>; } },
    { key: 'scope', label: 'Bound by', render: (item) => <span className="muted small mono">{boundCheckScope(item)}</span> },
    { key: 'evidence', label: 'Evidence level', render: (item) => <EvidenceModeCell item={item} check={checkById.get(getString(item, ['check_id', 'id'], ''))} /> }
  ];

  const verificationHistoryColumns: TableColumn<DataItem>[] = [
    { key: 'state', label: 'Recorded state', render: (item) => {
      const state = getString(item, ['state'], 'unknown');
      return <VerifyChip state={state} provenance={`Recorded target verification transition ${state}`} label={plainVerificationLabel(state)} />;
    } },
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
  const edgeDetection = detail.edge_detection ?? null;
  const edgeStatus = getString(edgeDetection, ['status'], 'inconclusive');
  const edgeReason = getString(edgeDetection, ['reason'], '');
  const edgeWaf = asDataItem(edgeDetection?.waf);
  const edgeCdn = asDataItem(edgeDetection?.cdn);
  const edgeWafProviders = stringList(edgeDetection?.waf_providers);
  const edgeCdnProviders = stringList(edgeDetection?.cdn_providers);
  const edgeCloud = asDataItem(edgeDetection?.cloud);
  const edgeCloudProviders = stringList(edgeDetection?.cloud_providers);
  const edgeConfidence = edgeConfidenceLabel(edgeDetection?.confidence);
  const edgeEvidence = asDataItem(edgeDetection?.evidence);
  const edgeVendorMatches = dataItemList(edgeEvidence?.vendor_matches, 5);
  const edgeWafw00f = asDataItem(edgeEvidence?.wafw00f);
  const edgeWafw00fGeneric = asDataItem(edgeWafw00f?.generic);
  const edgeCdncheck = asDataItem(edgeEvidence?.cdncheck);
  const edgeCnameChain = stringList(edgeEvidence?.dns_cname_chain);
  const edgeResolvedIps = stringList(edgeEvidence?.dns_resolved_ips);
  const edgeTestRunId = getString(edgeDetection, ['test_run_id'], '');
  const edgeObservedAt = edgeDetection?.observed_at ?? edgeDetection?.updated_at ?? null;
  const edgeReasonExplanation = edgeDetectionReasonExplanation(edgeReason);
  const edgeRequestStatus = getString(edgeRequestResult, ['status'], getString(edgeRequest, ['run_status'], 'unknown'));
  const edgeRequestReason = getString(edgeRequestResult, ['reason'], '');
  const edgeRequestExplanation = edgeRequestResult?.read_error
    ? `Run status ${formatTargetLabel(getString(edgeRequest, ['run_status'], 'unknown')).toLowerCase()}; the detection result could not be read (${String(edgeRequestResult.read_error)}).`
    : edgeDetectionReasonExplanation(edgeRequestReason) || (edgeRequestReason ? `Reported reason: ${formatTargetLabel(edgeRequestReason)}.` : '');
  const edgeRequestAt = edgeRequest?.completed_at ?? edgeRequest?.started_at ?? null;
  const edgeVendorColumns: TableColumn<DataItem>[] = [
    { key: 'vendor', label: 'Vendor', render: (item) => <span>{getString(item, ['name', 'vendor'], 'Not reported')}</span> },
    { key: 'confidence', label: 'Confidence', render: (item) => <span className="mono">{edgeConfidenceLabel(item.confidence) || 'Not reported'}</span> },
    { key: 'signals', label: 'Matched signals', render: (item) => {
      const signals = dataItemList(item.matched_signals, 4);
      if (signals.length === 0) return <span className="muted">Not reported</span>;
      return (
        <span className="edge-chip-row">
          {signals.map((signal, index) => (
            <Badge
              key={`${getString(signal, ['signal'], 'signal')}-${index}`}
              tone="muted"
              mono
              title={`Corpus tier ${getString(signal, ['tier'], 'unknown')}`}
            >
              {plainCodeLabel(getString(signal, ['signal'], 'Not reported'))}
            </Badge>
          ))}
        </span>
      );
    } }
  ];
  const ownershipMethod = ownershipMethodLabel(verification);
  const expectedBehavior = getString(target, ['expected_behavior', 'expected'], '—');
  const reportedEligibilityReason = getString(target, ['eligibility_reason'], '');
  const eligibilityReason = reportedEligibilityReason
    ? `Recorded eligibility reason: ${formatTargetLabel(reportedEligibilityReason)}.`
    : targetEligible
      ? 'The recorded ownership state makes this target eligible.'
      : 'No explicitly eligible ownership state is recorded, so validation remains locked.';
  const apiProtectionSummary = getString(edgeDetection, ['plain_language_summary', 'protection_summary'], '')
    || getString(wafPosture, ['plain_language_summary', 'protection_summary'], '');
  const wafValidation = asDataItem(wafPosture?.validation);
  const wafValidationVerdict = getString(wafValidation, ['verdict'], '');
  const wafValidationRunId = getString(wafValidation, ['run_id'], '');
  const wafPostureState = getString(wafPosture, ['posture', 'status'], '');
  const wafLayerState = getString(edgeWaf, ['status'], wafPostureState || 'unknown');
  const wafLayerProvider = getString(edgeWaf, ['provider'], getString(wafPosture, ['vendor'], ''));
  const cdnLayerState = getString(edgeCdn, ['status'], 'unknown');
  const cdnLayerProvider = getString(edgeCdn, ['provider'], '');
  const cloudLayerState = getString(edgeCloud, ['status'], 'unknown');
  const cloudLayerProvider = getString(edgeCloud, ['provider'], '');
  const edgeNetworkFirewall = asDataItem(edgeDetection?.network_firewall);
  const edgeDirectOrigin = asDataItem(edgeNetworkFirewall?.direct_origin_reachability);
  const edgePortExposure = asDataItem(edgeNetworkFirewall?.port_exposure);
  const originBypass = asDataItem(wafPosture?.origin_bypass);
  const originLayerState = getString(edgeDirectOrigin, ['status'], getString(originBypass, ['state'], 'unknown'));
  const originCheckedAt = edgeDirectOrigin ? edgeObservedAt : originBypass?.last_checked_at ?? null;
  const openPorts = Array.isArray(edgePortExposure?.open_ports) ? edgePortExposure.open_ports.length : 0;
  const edgeEffectiveness = asDataItem(edgeDetection?.effectiveness);
  const edgeEffectivenessStatus = getString(edgeEffectiveness, ['status'], '');
  const edgeEffectivenessTier = evidenceTierInfo(getString(edgeEffectiveness, ['evidence_tier'], ''));
  const blockedProbeCount = getOptionalNumber(edgeEffectiveness, ['blocked_count']);
  const testedProbeCount = getOptionalNumber(edgeEffectiveness, ['tested_count']);
  const blockedProbePercent = getOptionalNumber(edgeEffectiveness, ['percentage']);
  const hasEdgeEffectivenessScore = Boolean(
    edgeEffectivenessStatus
    && testedProbeCount !== null
    && testedProbeCount > 0
    && blockedProbeCount !== null
  );
  const fallbackProtectionSummary = wafValidationVerdict && wafValidationRunId
    ? `${plainVerdictLabel(wafValidationVerdict)} in the linked WAF validation. This conclusion applies only to that tested scenario.`
    : edgeDetection
      ? edgeStatus === 'detected'
        ? 'A live edge check detected one or more protection or hosting layers. Detection alone does not prove they blocked the test.'
        : edgeStatus === 'not_detected'
          ? 'The latest live edge check did not identify a WAF or CDN. This does not prove that no edge control exists.'
          : 'The latest edge check did not produce enough evidence for a protection conclusion.'
      : wafPosture
        ? `Linked WAF posture is available: ${plainProtectionLabel(wafPostureState)}. Open the evidence below before treating it as a broad readiness claim.`
        : 'Protection layers have not been tested live for this target yet.';
  const protectionSummary = apiProtectionSummary || fallbackProtectionSummary;
  const scoredEffectivenessLabel = hasEdgeEffectivenessScore
    ? `${blockedProbeCount} of ${testedProbeCount} safe probes blocked${blockedProbePercent === null ? '' : ` (${Math.round(blockedProbePercent)}%)`}`
    : '';
  const wafEffectivenessLabel = scoredEffectivenessLabel
    || (wafValidationVerdict && wafValidationRunId
      ? plainVerdictLabel(wafValidationVerdict)
      : wafLayerState === 'detected'
        ? 'Detected, not tested for effectiveness'
        : 'Not tested live');
  const wafEffectivenessTone: StatTone = hasEdgeEffectivenessScore
    ? edgeEffectivenessStatus === 'effective_for_tested_probes' ? 'success' : 'warn'
    : wafValidationVerdict && wafValidationRunId
      ? runOutcomeTone(wafValidationVerdict)
      : wafLayerState === 'detected' ? 'warn' : 'muted';
  const wafEffectivenessStep = hasEdgeEffectivenessScore
    ? edgeEffectivenessStatus === 'effective_for_tested_probes' ? 2 : 1
    : wafValidationVerdict && wafValidationRunId
      ? ['pass', 'passed', 'protected', 'success'].includes(wafValidationVerdict.toLowerCase()) ? 2 : 1
      : 0;
  const wafEffectivenessSourceId = hasEdgeEffectivenessScore ? edgeTestRunId : wafValidationRunId;
  const wafEffectivenessTechnicalState = hasEdgeEffectivenessScore ? edgeEffectivenessStatus : wafValidationVerdict;
  const wafEffectivenessDetail = hasEdgeEffectivenessScore
    ? `${edgeEffectivenessTier ? `${edgeEffectivenessTier.label} (${edgeEffectivenessTier.code}). ` : ''}Based on ${testedProbeCount} safe probes from ${edgeTestRunId || 'the recorded edge result'}; untested scenarios are not covered.`
    : wafValidationRunId
      ? 'Based on the linked validation; untested scenarios are not covered.'
      : 'Detection alone cannot show whether the WAF blocked traffic.';
  const effectivenessSteps = ['Not tested', 'Needs attention', 'Worked in tested scenario'];
  const protectionLayers: Array<{ icon: typeof Activity; label: string; value: string; detail: string; technicalState: string; tone: StatTone }> = [
    {
      icon: ShieldCheck,
      label: 'Web application firewall',
      value: plainProtectionLabel(wafLayerState),
      detail: wafLayerProvider ? `Provider reported as ${wafLayerProvider}.` : 'No WAF provider was asserted.',
      technicalState: wafLayerState,
      tone: protectionStateTone(wafLayerState),
    },
    {
      icon: Network,
      label: 'CDN / edge network',
      value: plainProtectionLabel(cdnLayerState),
      detail: cdnLayerProvider ? `Provider reported as ${cdnLayerProvider}.` : 'No CDN provider was asserted by a live edge result.',
      technicalState: cdnLayerState === 'unknown' ? '' : cdnLayerState,
      tone: protectionStateTone(cdnLayerState),
    },
    {
      icon: Cloud,
      label: 'Cloud hosting',
      value: plainProtectionLabel(cloudLayerState),
      detail: cloudLayerProvider ? `Hosting range matched ${cloudLayerProvider}; hosting is not proof of protection.` : 'Hosting was not asserted; hosting alone would not prove protection.',
      technicalState: cloudLayerState === 'unknown' ? '' : cloudLayerState,
      tone: protectionStateTone(cloudLayerState),
    },
    {
      icon: Server,
      label: 'Origin access / firewall',
      value: plainProtectionLabel(originLayerState),
      detail: originCheckedAt
        ? `Last direct-path check: ${formatDate(originCheckedAt)}.${openPorts > 0 ? ` ${openPorts} exposed port${openPorts === 1 ? '' : 's'} reported.` : ''}`
        : 'Direct-origin reachability and exposed ports were not reported as tested.',
      technicalState: originLayerState === 'unknown' ? '' : originLayerState,
      tone: protectionStateTone(originLayerState),
    },
  ];

  return (
    <div className="content target-detail-view">
      {renderHeader()}
      {error ? <div className="form-banner error" role="alert">{error}</div> : null}
      {startedRunId && !error ? (
        <div className="form-banner" role="status">
          Bounded run started for {effectiveSelectedRunCheckId || 'the selected check'}.
          {startedRunId !== 'started' ? <> <DetailEntityLink route="run-detail" id={startedRunId} label="Open run" /></> : null}
        </div>
      ) : null}

      <Card className="target-protection-card" data-testid="target-protection-summary">
        <CardHeader>
          <div>
            <CardTitle>Protection at a glance</CardTitle>
            <CardDescription>What sits in front of this target, what was checked, and how strong the evidence is.</CardDescription>
          </div>
          <Badge
            tone={apiProtectionSummary ? 'info' : wafValidationRunId ? 'success' : edgeDetection ? 'info' : 'warn'}
            title={apiProtectionSummary ? 'Summary recorded with the latest edge evidence.' : 'Cautious summary derived only from recorded evidence fields.'}
          >
            {apiProtectionSummary ? 'Recorded summary' : wafValidationRunId ? 'Linked validation' : edgeDetection ? 'Live edge check' : 'Evidence limited'}
          </Badge>
        </CardHeader>
        <CardContent>
          <p className="target-protection-lede">{protectionSummary}</p>
          <p className="target-protection-source">
            {apiProtectionSummary ? 'This wording was recorded with the latest evidence.' : 'AstraNull generated this cautious fallback from the recorded evidence fields.'}
          </p>
          <div className="target-protection-grid" aria-label="Detected and reported protection layers">
            {protectionLayers.map((layer) => <ProtectionLayer key={layer.label} {...layer} />)}
          </div>
          <section className="waf-effectiveness" aria-labelledby="target-waf-effectiveness-title">
            <div className="waf-effectiveness-copy">
              <h3 id="target-waf-effectiveness-title">WAF effectiveness</h3>
              <Badge tone={wafEffectivenessTone} title={wafEffectivenessSourceId ? `Evidence source ${wafEffectivenessSourceId}; technical state ${wafEffectivenessTechnicalState || 'not reported'}.` : 'No evidence-backed WAF effectiveness result was reported.'}>{wafEffectivenessLabel}</Badge>
              <p>{wafEffectivenessDetail}</p>
            </div>
            <div className="effectiveness-scale" role="img" aria-label={`WAF effectiveness: ${wafEffectivenessLabel}`}>
              {effectivenessSteps.map((label, index) => (
                <span key={label} className="effectiveness-step" aria-current={index === wafEffectivenessStep ? 'true' : undefined}>{label}</span>
              ))}
            </div>
          </section>
          <EvidenceGuide compact />
        </CardContent>
      </Card>

      <Card className="target-verification-card">
        <CardHeader>
          <div>
            <CardTitle>Verification ladder</CardTitle>
            <CardDescription>Recorded ownership evidence for this exact target. Steps are not inferred from target-group membership or a missing transition.</CardDescription>
          </div>
          <VerifyChip state={verificationState} provenance={provenance} strong label={plainVerificationLabel(verificationState)} />
        </CardHeader>
        <CardContent>
          <ol className="verify-ladder" aria-label="Target ownership verification ladder">
            {verificationLadder.map((step, index) => {
              const now = !step.done && verificationLadder.slice(0, index).every((entry) => entry.done);
              return (
                <li key={step.id} className={`vl-step${step.done ? ' is-done' : ''}${now ? ' is-now' : ''}`}>
                  <span className="vl-num" aria-hidden="true">{step.done ? <Check size={13} strokeWidth={2.6} /> : index + 1}</span>
                  <div className="vl-body"><strong>{step.label}</strong><span className="vl-meta">{step.meta}</span></div>
                </li>
              );
            })}
          </ol>
          <div className="callout target-eligibility-callout" data-eligible={String(targetEligible)}>
            <span className="callout-icon" aria-hidden="true"><ShieldCheck size={18} /></span>
            <div className="callout-body">
              <p className="callout-title"><Badge tone={targetEligible ? 'success' : 'warn'}>{eligibilityDisplay}</Badge> for validation</p>
              <p className="callout-desc">{eligibilityReason}</p>
            </div>
          </div>
          {verificationHistory.length > 0 ? (
            <details className="target-history technical-disclosure">
              <summary>Show recorded verification transitions</summary>
              <div className="target-history-head">
                <h3>Recorded verification transitions</h3>
                <span className="muted small">Duplicate records removed · oldest to newest</span>
              </div>
              <DataTable
                columns={verificationHistoryColumns}
                items={verificationHistory}
                getRowId={(item, index) => `${getString(item, ['state'], 'unknown')}-${getString(item, ['transitioned_at'], String(index))}-${index}`}
                empty={<span className="muted">No verification transitions reported.</span>}
              />
            </details>
          ) : null}
        </CardContent>
      </Card>

      <div className="metric-grid four">
        <MetricCard label="Kind" value={formatTargetLabel(kind)} sub="Declared target type" icon={Target} tone="info" />
        <MetricCard label="Expected behavior" value={formatTargetLabel(getString(target, ['expected_behavior', 'expected'], '—'))} sub="Declared expectation" icon={Activity} tone="muted" />
        <MetricCard label="Verification" value={plainVerificationLabel(verificationState)} sub="Recorded ownership signal" icon={ShieldCheck} tone={verificationTone(verificationState)} />
        <MetricCard label="Eligibility" value={eligibilityDisplay} sub={targetEligible ? 'Explicitly eligible for checks' : 'Validation locked (fail closed)'} icon={FileCheck2} tone={targetEligible ? 'success' : 'warn'} />
      </div>

      <Card className="target-facts-card">
        <CardHeader>
          <div>
            <CardTitle>Target facts</CardTitle>
            <CardDescription>Declared inventory, ownership evidence, relationships, and authorization for this target.</CardDescription>
          </div>
        </CardHeader>
        <CardContent>
          <div className="table-wrap" tabIndex={0} role="region" aria-label="Ownership and eligibility, scrollable">
            <table className="data-table">
              <tbody>
                <tr><td className="muted">Target ID</td><td><div className="kv"><span className="mono">{entityId}</span></div></td></tr>
                <tr><td className="muted">Declared value</td><td><div className="kv"><span className="mono">{targetDisplayValue(target)}</span></div></td></tr>
                <tr><td className="muted">Kind</td><td><div className="kv"><span>{formatTargetLabel(kind)}</span></div></td></tr>
                <tr><td className="muted">Declaration source</td><td><div className="kv"><span>{declarationProvenance}</span></div></td></tr>
                <tr><td className="muted">Ownership method</td><td><div className="kv"><span className="mono">{ownershipMethod}</span></div></td></tr>
                <tr><td className="muted">Ownership status</td><td><div className="kv"><VerifyChip state={verificationState} provenance={provenance} label={plainVerificationLabel(verificationState)} /></div></td></tr>
                <tr><td className="muted">Target group</td><td><div className="kv"><DetailEntityLink route="target-group-detail" id={getString(target, ['target_group_id'], '')} /></div></td></tr>
                <tr><td className="muted">Environment</td><td><div className="kv"><span className="mono">{getString(target, ['environment_id'], 'Not reported')}</span></div></td></tr>
                <tr><td className="muted">Expected behavior</td><td><div className="kv"><span>{formatTargetLabel(expectedBehavior)}</span></div></td></tr>
                {agentBinding ? (
                  <tr><td className="muted">Agent binding</td><td><div className="kv"><span className="mono">{agentBindingId}</span>{agentBindingAt ? <span className="kv-meta">{formatDate(agentBindingAt)}</span> : null}</div></td></tr>
                ) : null}
                <tr><td className="muted">Group LOA</td><td><div className="kv"><Badge tone={loaSigned ? 'success' : loaState ? 'warn' : 'muted'} title="Recorded letter-of-authorization state">{loaState ? formatTargetLabel(loaState) : 'Not reported'}</Badge>{loaCustody ? <span className="kv-meta">{loaCustody}</span> : null}</div></td></tr>
                {loaSigner ? (
                  <tr><td className="muted">LOA signer</td><td><div className="kv"><span>{loaSigner}</span>{loaSignedAt ? <span className="kv-meta">{formatDate(loaSignedAt)}</span> : null}</div></td></tr>
                ) : null}
              </tbody>
            </table>
          </div>
        </CardContent>
      </Card>

      {showWaf ? (
        <Card>
          <CardHeader><CardTitle>WAF posture</CardTitle><CardDescription>Linked WAF posture for this target.</CardDescription></CardHeader>
          <CardContent>
            <div className="kpi-row">
              <div className="kpi-cell"><div className="kpi-label">Posture</div><div className="kpi-value">{plainProtectionLabel(wafPostureState)}</div></div>
              <div className="kpi-cell"><div className="kpi-label">Drift</div><div className="kpi-value">{wafPosture?.drift_reason ? 'Configuration changed' : 'No drift reported'}</div></div>
              <div className="kpi-cell"><div className="kpi-label">Validation result</div><div className="kpi-value">{wafValidationVerdict ? plainVerdictLabel(wafValidationVerdict) : 'Not reported'}</div></div>
              <div className="kpi-cell"><div className="kpi-label">Data connection</div><div className="kpi-value">{plainProtectionLabel(getString(wafPosture?.connector as DataItem | undefined, ['state'], 'unknown'))}</div></div>
              <div className="kpi-cell"><div className="kpi-label">Fingerprint</div><div className="kpi-value" title={getString(wafPosture?.fingerprint as DataItem | undefined, ['signature'], 'Not reported')}>{getString(wafPosture?.fingerprint as DataItem | undefined, ['signature'], '') ? 'Recorded' : 'Not reported'}</div></div>
              <div className="kpi-cell"><div className="kpi-label">Marker rules</div><div className="kpi-value">{String(wafPosture?.marker_rules ?? '—')}</div></div>
              <div className="kpi-cell"><div className="kpi-label">Origin bypass</div><div className="kpi-value">{plainProtectionLabel(getString(wafPosture?.origin_bypass as DataItem | undefined, ['state'], 'unknown'))}</div></div>
            </div>
            <p className="muted">{getString(wafPosture, ['plain_language_summary', 'protection_summary', 'notes', 'summary'], 'No additional WAF summary was returned.')}</p>
            <details className="technical-disclosure">
              <summary>Show technical WAF record</summary>
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
            </details>
          </CardContent>
        </Card>
      ) : null}

      <Card>
        <CardHeader>
          <div>
            <CardTitle>WAF / CDN edge detection</CardTitle>
            <CardDescription>Recorded fingerprint evidence for this target. Provider names appear only when the evidence names them; AstraNull does not guess the source.</CardDescription>
          </div>
          {edgeDetection ? (
            <Badge
              tone={edgeStatusTone(edgeStatus)}
              title={`Edge detection status ${edgeStatus}${edgeReason ? ` · reason ${edgeReason}` : ''}`}
            >
              {plainProtectionLabel(edgeStatus)}
            </Badge>
          ) : showEdgeRequest ? (
            <Badge tone={edgeStatusTone(edgeRequestStatus)} title={`Latest detection request ${edgeRequestId}`}>{`Latest request: ${formatTargetLabel(edgeRequestStatus)}`}</Badge>
          ) : (
            <Badge tone="muted">Not detected yet</Badge>
          )}
        </CardHeader>
        <CardContent>
          {showEdgeRequest ? (
            <div className="target-selection-note edge-request-status" role="status">
              <span>Latest detection request</span>
              <DetailEntityLink route="run-detail" id={edgeRequestId} />
              <Badge tone={edgeStatusTone(edgeRequestStatus)}>{formatTargetLabel(edgeRequestStatus)}</Badge>
              {edgeRequestAt ? <span className="muted small">{formatDate(edgeRequestAt)}</span> : null}
              {edgeRequestExplanation ? <span>{edgeRequestExplanation}</span> : edgeRequestResult ? null : <span className="muted">Reading detection result…</span>}
            </div>
          ) : null}
          {edgeDetection ? (
            <>
              <div className="kpi-row">
                <div className="kpi-cell"><div className="kpi-label">Overall</div><div className="kpi-value">{plainProtectionLabel(edgeStatus)}</div></div>
                <div className="kpi-cell"><div className="kpi-label">Confidence</div><div className="kpi-value">{edgeConfidence || 'Not reported'}</div></div>
                <div className="kpi-cell"><div className="kpi-label">Corpus version</div><div className="kpi-value mono">{getString(edgeDetection, ['corpus_version'], 'Not reported')}</div></div>
                <div className="kpi-cell"><div className="kpi-label">Observed</div><div className="kpi-value">{edgeObservedAt ? formatDate(edgeObservedAt) : 'Not reported'}</div></div>
                <div className="kpi-cell"><div className="kpi-label">Source run</div><div className="kpi-value">{edgeTestRunId ? <DetailEntityLink route="run-detail" id={edgeTestRunId} /> : <span className="mono">Not reported</span>}</div></div>
              </div>
              {edgeReason ? <p className="muted">Reported reason: {formatTargetLabel(edgeReason)}.{edgeReasonExplanation ? ` ${edgeReasonExplanation}` : ''}</p> : null}
              {edgeDetection.conflicting_vendor_signals === true ? (
                <p className="muted">Vendor signals conflict, so no single WAF provider is asserted.</p>
              ) : null}

              <div className="edge-family-grid" aria-label="Independent WAF, CDN, and cloud hosting detection">
                <section className="edge-family-card" aria-labelledby="target-edge-waf-title">
                  <div className="edge-family-card-head">
                    <strong id="target-edge-waf-title">WAF</strong>
                    <Badge
                      tone={edgeStatusTone(getString(edgeWaf, ['status'], 'inconclusive'))}
                      title="WAF fingerprint status recorded for this target"
                    >
                      {formatTargetLabel(getString(edgeWaf, ['status'], 'inconclusive'))}
                    </Badge>
                  </div>
                  <dl>
                    <dt>Provider</dt><dd>{getString(edgeWaf, ['provider'], 'Not asserted')}</dd>
                    <dt>Type</dt><dd>{formatTargetLabel(getString(edgeWaf, ['type'], ''), 'Not reported')}</dd>
                    <EdgeFamilyProviders family={edgeWaf} providers={edgeWafProviders} />
                  </dl>
                </section>
                <section className="edge-family-card" aria-labelledby="target-edge-cdn-title">
                  <div className="edge-family-card-head">
                    <strong id="target-edge-cdn-title">CDN</strong>
                    <Badge
                      tone={edgeStatusTone(getString(edgeCdn, ['status'], 'inconclusive'))}
                      title="CDN fingerprint status recorded for this target"
                    >
                      {formatTargetLabel(getString(edgeCdn, ['status'], 'inconclusive'))}
                    </Badge>
                  </div>
                  <dl>
                    <dt>Provider</dt><dd>{getString(edgeCdn, ['provider'], 'Not asserted')}</dd>
                    <dt>Type</dt><dd>{formatTargetLabel(getString(edgeCdn, ['type'], ''), 'Not reported')}</dd>
                    <EdgeFamilyProviders family={edgeCdn} providers={edgeCdnProviders} />
                  </dl>
                </section>
                <section className="edge-family-card" aria-labelledby="target-edge-cloud-title">
                  <div className="edge-family-card-head">
                    <strong id="target-edge-cloud-title">Cloud hosting</strong>
                    <Badge
                      tone={edgeStatusTone(getString(edgeCloud, ['status'], 'inconclusive'))}
                      title="cdncheck cloud range membership for the resolved addresses"
                    >
                      {formatTargetLabel(getString(edgeCloud, ['status'], 'inconclusive'))}
                    </Badge>
                  </div>
                  <dl>
                    <dt>Provider</dt><dd>{getString(edgeCloud, ['provider'], 'Not asserted')}</dd>
                    <dt>Type</dt><dd>{formatTargetLabel(getString(edgeCloud, ['type'], ''), 'Not reported')}</dd>
                    <EdgeFamilyProviders family={edgeCloud} providers={edgeCloudProviders} />
                  </dl>
                </section>
              </div>

              <div className="edge-evidence-block">
                <h3 id="target-edge-verdicts-title">Tool verdicts</h3>
                <div className="edge-family-grid" aria-labelledby="target-edge-verdicts-title">
                  <section className="edge-family-card" aria-label="wafw00f verdict">
                    <div className="edge-family-card-head">
                      <strong>wafw00f</strong>
                      <Badge tone={edgeWafw00f?.detected === true ? 'success' : edgeWafw00f ? 'muted' : 'warn'}>
                        {edgeWafw00f ? (edgeWafw00f.detected === true ? 'WAF detected' : 'No WAF detected') : 'Not reported'}
                      </Badge>
                    </div>
                    <dl>
                      <dt>Firewall</dt><dd>{getString(edgeWafw00f, ['firewall'], 'Not reported')}</dd>
                      <dt>Manufacturer</dt><dd>{getString(edgeWafw00f, ['manufacturer'], 'Not reported')}</dd>
                      <dt>All matches</dt><dd>{stringList(edgeWafw00f?.all_matches).join(', ') || 'None'}</dd>
                      <dt>Generic reason</dt>
                      <dd>{edgeWafw00fGeneric?.found === true ? getString(edgeWafw00fGeneric, ['reason'], 'Reported') : 'Not triggered'}</dd>
                    </dl>
                  </section>
                  <section className="edge-family-card" aria-label="cdncheck verdict">
                    <div className="edge-family-card-head">
                      <strong>cdncheck</strong>
                      <Badge tone={edgeCdncheck?.matched === true ? 'success' : edgeCdncheck ? 'muted' : 'warn'}>
                        {edgeCdncheck ? (edgeCdncheck.matched === true ? formatTargetLabel(getString(edgeCdncheck, ['item_type'], 'matched')) : 'No match') : 'DNS not observed'}
                      </Badge>
                    </div>
                    <dl>
                      <dt>Provider</dt><dd>{getString(edgeCdncheck, ['provider'], 'None')}</dd>
                      <dt>Matched via</dt><dd>{getString(edgeCdncheck, ['source'], 'None').toUpperCase()}</dd>
                      <dt>Matched value</dt><dd className="mono">{getString(edgeCdncheck, ['value'], 'None')}</dd>
                    </dl>
                  </section>
                </div>
                {edgeCnameChain.length > 0 ? (
                  <p className="edge-chain"><span className="edge-chain-label">CNAME chain</span><span className="mono">{edgeCnameChain.join(' → ')}</span></p>
                ) : null}
                {edgeResolvedIps.length > 0 ? (
                  <p className="edge-chain"><span className="edge-chain-label">Resolved addresses</span><span className="mono">{edgeResolvedIps.join(', ')}</span></p>
                ) : null}
              </div>

              <div className="edge-evidence-block">
                <h3 id="target-edge-vendor-title">Vendor fingerprint matches</h3>
                <DataTable
                  columns={edgeVendorColumns}
                  items={edgeVendorMatches}
                  getRowId={(item, index) => `${getString(item, ['vendor', 'name'], 'vendor')}-${index}`}
                  empty={<span className="muted">No vendor fingerprint matches were recorded.</span>}
                />
              </div>

              <p className="muted small">Fingerprint detection is not a protection verdict. A successful no-match does not prove that no edge control exists.</p>
            </>
          ) : (
            <p className="muted">{showEdgeRequest
              ? 'No durable edge detection has been recorded for this target. Only a trusted signed-worker result populates this section.'
              : 'No edge detection has been recorded for this target yet. Run WAF/CDN detection from the target group to populate this section.'}</p>
          )}
        </CardContent>
      </Card>

      <div className="target-detail-workspace">
        <Card>
          <CardHeader>
            <div><CardTitle>Bound checks</CardTitle><CardDescription>Select the exact customer-runnable check before starting a bounded run. Bindings are not presented as run history.</CardDescription></div>
            <div className="row-actions">
              <Badge tone={effectiveSelectedRunCheckId ? 'success' : 'warn'}>{effectiveSelectedRunCheckId ? 'Selected' : 'Selection required'}</Badge>
              {canStartBoundedRun ? (
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
              ) : <Badge tone="muted">Read-only role</Badge>}
            </div>
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
          <CardHeader><div><CardTitle>Recent runs</CardTitle><CardDescription>Latest runs for this target; duplicate records are shown once.</CardDescription></div></CardHeader>
          <CardContent>
            <DataTable columns={runColumns} items={runsRecent} empty={emptyStateFromApi({ icon: Activity, meta: detail.sectionMeta?.runs, actionHref: '#runs', actionLabel: 'Open test runs' })} />
            {runsRecent.length > 0 ? <p className="history-summary">Showing {runsRecent.length} recent unique run{runsRecent.length === 1 ? '' : 's'} for this target.</p> : null}
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
