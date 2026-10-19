import { checkPresentation } from '../lib/check-presentation.mjs';
import { useEffect, useMemo, useRef, useState } from 'react';
import type { HTMLAttributes, MouseEvent as ReactMouseEvent, ReactNode } from 'react';
import { Check, Eye, FileCheck2, TriangleAlert, Wrench } from 'lucide-react';
import { FindingExplanationPanel } from '../components/findings/finding-explanation-panel';
import { MissingControlCard } from '../components/findings/missing-control-card';
import { FindingDetectionHistory } from '../components/findings/finding-detection-history';
import { populateFindingAffectedTargets, populateFindingEvidence, readFindingRemediationFields } from '../lib/finding-detail';
import { readFindingLineage } from '../lib/finding-lineage.mjs';
import { useProgressiveFindings } from '../components/findings/use-server-findings';
import { VerifyChip, resolveTargetVerificationProvenance } from '../lib/verify-chip';
import { requestJson } from '../lib/api';
import { apiErrorMessage } from '../lib/error-messages';
import { sessionHasPermission } from '../lib/dataset-access.mjs';
import { buildDetailHref } from '../lib/route-params';
import type { DataItem, PortalConfig, PortalData, Session } from '../lib/types';
import { formatAuditAction, formatDate, formatSeverityLabel, formatTimestamp, triggerJsonDownload } from '../lib/utils';
import { AnchorButton, Button } from '../components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../components/ui/card';
import { EmptyState } from '../components/ui/empty-state';
import { RoleRestrictedCard } from '../components/ui/role-restricted';
import { Toast } from '../components/ui/toast';
import { RiskAcceptanceDialog, type RiskAcceptanceInput } from '../components/findings/risk-acceptance-dialog';
import { PortalLoadingSkeleton } from '../lib/empty-from-api';
// @ts-ignore Plain ESM keeps executive labels directly testable with node:test.
import { plainCheckName, plainCodeLabel, plainEmptyReason, plainFindingTitle, plainVerdictLabel } from '../lib/plain-language.mjs';
import { Badge, type BadgeProps } from '../components/ui/badge';
import { DataTable, type TableColumn } from '../components/ui/table';
import {
  FINDING_RULE_ASSETS_FOCUS,
  countFindingAssets,
  findingAssetLabel,
  findingObservationLabel,
  findingObservedAt,
  findingOpenedAt,
  findingRuleSiblings,
  findingRuleTitle,
  findingSlaDueAt,
  findingStatus as readFindingStatus,
  isFindingSlaBreach,
  resolveFindingRetestAction
} from '../lib/findings-helpers';
import '../components/findings/findings-groups.css';
import './finding-detail-view.css';
import { ConfirmModal, useConfirmModal } from '../lib/crud-ui';
import { useInspectorRef, useOpenInspector } from '../components/evidence/use-inspector';
import { getRouteParam, replaceRouteParams } from '../lib/route-params';
import { findingStatusTone } from '../lib/status-tone';
import { severityTone } from '../lib/severity-tone';
import { FindingStatusBadge } from './refined/findings-refined';
import { DetailBackLink } from '../components/layout/detail-back-link';
import { AskAiButton } from '../components/assistant/ask-ai-button';
import { VerdictReplay } from '../components/runs/verdict-replay';
import { useEntityDocumentTitle } from '../components/layout/app-shell';
import { FINDING_STATUS_DESCRIPTIONS, FINDING_STATUS_LABELS, findingStatusTransitions, type FindingStatus } from '../lib/findings-query.mjs';
import { findingDecisionNote, findingStatusBucket } from '../lib/finding-groups.mjs';
import { fixVerifiedBasis } from '../lib/finding-lifecycle.mjs';
import { usePublishAssistantContext } from '../lib/assistant-page-store';

type StatTone = NonNullable<BadgeProps['tone']>;

const FINDING_DETAIL_STYLES_ID = 'finding-detail-view-styles';
const findingDetailStyles = `
.finding-detail-page { gap: var(--space-6); }
.finding-detail-page > .page-head { margin-bottom: 0; }
.finding-detail-page .finding-title-copy { min-width: 0; }
.finding-detail-page .finding-title-copy .page-title,
.finding-detail-page .finding-id { overflow-wrap: anywhere; word-break: break-word; }
.finding-detail-page .finding-summary-facts { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 0 var(--space-4); margin: 0; }
.finding-detail-page .finding-summary-fact { min-width: 0; padding: var(--space-3) 0; border-top: 1px solid var(--border-soft); }
.finding-detail-page .finding-summary-fact dt { margin-bottom: var(--space-1); color: var(--muted); font-family: var(--font-mono); font-size: var(--text-xs); letter-spacing: var(--tracking-caps); text-transform: uppercase; }
.finding-detail-page .finding-summary-fact dd { min-width: 0; margin: 0; color: var(--fg); font-size: var(--text-sm); overflow-wrap: anywhere; word-break: break-word; }
.finding-detail-page .finding-relations { display: flex; align-items: center; gap: var(--space-2); flex-wrap: wrap; margin-top: var(--space-4); }
.finding-detail-page .finding-relations .btn { max-width: 100%; white-space: normal; overflow-wrap: anywhere; text-align: start; }
.finding-detail-page .finding-decision-ladder { grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); margin-bottom: var(--space-4); }
.finding-detail-page .data-table .mono.finding-digest { display: inline-block; min-width: 32ch; max-width: 42ch; overflow-wrap: anywhere; white-space: normal; }
.finding-detail-page .entity-cell-stack { min-width: 160px; }
.finding-detail-page .finding-artifact-row { cursor: pointer; }
.finding-detail-page .finding-summary-fact dd small { display: block; margin-top: 2px; color: var(--fg-2); }
.finding-detail-page .finding-lineage { display: grid; margin-top: var(--space-4); }
.finding-detail-page .finding-lineage-item { display: grid; align-content: start; gap: var(--space-1); min-width: 0; padding: var(--space-3) 0; border-top: 1px solid var(--border-soft); font-size: var(--text-sm); overflow-wrap: anywhere; }
.finding-detail-page .finding-lineage-label { color: var(--fg-2); font-size: var(--text-sm); font-weight: 600; }
.finding-detail-page .finding-closure-basis { display: grid; gap: var(--space-1); }
.finding-detail-page .finding-closure-basis > strong { color: var(--fg); font-weight: 600; line-height: 1.4; }
.finding-detail-page .finding-closure-basis > span { color: var(--fg-2); line-height: 1.5; max-width: 72ch; }
.finding-detail-page .finding-risk-reason { color: var(--fg-2); white-space: pre-wrap; }
.finding-detail-page .finding-triage-group { display: grid; gap: var(--space-2); }
.finding-detail-page .finding-triage-group-label { color: var(--fg); font-size: var(--text-sm); font-weight: 600; margin: 0; }
.finding-detail-page .finding-decision-group { display: grid; gap: var(--space-3); margin-top: var(--space-4); padding-top: var(--space-4); border-top: 1px solid var(--border-soft); }
.finding-detail-page .finding-decision-current { display: flex; flex-wrap: wrap; align-items: center; gap: var(--space-2); color: var(--fg-2); font-size: var(--text-sm); }
.finding-detail-page .finding-decision-actions { display: flex; flex-wrap: wrap; gap: var(--space-2); }
.finding-detail-page .finding-recorded-explanation { display: grid; gap: var(--space-1); margin: 0 0 var(--space-4); padding: var(--space-3) var(--space-4); border: 1px solid var(--border-soft); border-radius: var(--radius-md); background: var(--surface-sunk); font-size: var(--text-sm); }
.finding-detail-page .finding-recorded-explanation p { margin: 0; color: var(--fg); white-space: pre-wrap; overflow-wrap: anywhere; }
.finding-detail-page .finding-recorded-explanation small { color: var(--fg-2); }
.finding-detail-page .finding-triage-readonly .finding-notes-value { white-space: pre-wrap; overflow-wrap: anywhere; }
.finding-detail-page .finding-decision-history { display: grid; gap: var(--space-2); margin: var(--space-4) 0 0; padding: var(--space-4) 0 0; border-top: 1px solid var(--border-soft); }
.finding-detail-page .finding-decision-history h3 { margin: 0; font-size: var(--text-sm); font-weight: 600; color: var(--fg); }
.finding-detail-page .finding-decision-history ol { display: grid; gap: var(--space-2); margin: 0; padding: 0; list-style: none; }
.finding-detail-page .finding-decision-history li { display: grid; gap: var(--space-1); padding: var(--space-2) 0; border-top: 1px solid var(--border-soft); font-size: var(--text-sm); overflow-wrap: anywhere; }
.finding-detail-page .finding-decision-history li:first-child { border-top: 0; }
.finding-detail-page .finding-decision-history .finding-history-meta { color: var(--fg-2); font-size: var(--text-xs); }
.finding-detail-page .finding-decision-history .finding-history-notes { color: var(--fg-2); white-space: pre-wrap; }
.finding-detail-page .rule-assets-more { display: flex; flex-wrap: wrap; align-items: center; gap: var(--space-2) var(--space-3); margin-bottom: var(--space-3); }
.finding-detail-page .finding-lineage-runs { display: grid; gap: var(--space-1); margin: 0; padding: 0; list-style: none; }
.finding-detail-page .finding-lineage-runs li { display: flex; flex-wrap: wrap; align-items: center; gap: var(--space-2); }
.finding-detail-page .finding-custody-card .code { max-width: 100%; white-space: pre; }
@media (max-width: 1100px) {
  .finding-detail-page .finding-decision-ladder { grid-template-columns: repeat(2, minmax(0, 1fr)); }
}
@media (max-width: 720px) {
  .finding-detail-page .finding-summary-facts,
  .finding-detail-page .finding-decision-ladder { grid-template-columns: minmax(0, 1fr); }
}
@media (max-width: 640px) {
  .finding-detail-page .product-form--compact .row-actions.action-bar-compact { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); justify-content: start; align-items: stretch; }
  .finding-detail-page .product-form--compact .row-actions.action-bar-compact .btn,
  .finding-detail-page .finding-decision-actions .btn { width: 100%; min-height: 44px; }
  .finding-detail-page .finding-decision-actions { display: grid; grid-template-columns: minmax(0, 1fr); }
}
`;

function ensureFindingDetailStyles() {
  if (typeof document === 'undefined' || document.getElementById(FINDING_DETAIL_STYLES_ID)) return;
  const node = document.createElement('style');
  node.id = FINDING_DETAIL_STYLES_ID;
  node.textContent = findingDetailStyles;
  document.head.appendChild(node);
}

type FindingDecisionStep = { id: string; label: string; done: boolean; meta: string };

const DECISION_STATUSES = ['accepted_risk', 'accepted', 'fix_verified', 'resolved', 'closed', 'false_positive'];
const CLOSED_OUTCOMES = ['fix_verified', 'resolved', 'closed', 'false_positive'];
const REASONED_OUTCOMES: Partial<Record<FindingStatus, { title: string; confirmLabel: string; noteLabel: string }>> = {
  resolved: { title: 'Mark this finding resolved', confirmLabel: 'Mark resolved', noteLabel: 'Resolved' },
  false_positive: { title: 'Mark this finding a false positive', confirmLabel: 'Mark false positive', noteLabel: 'Marked false positive' },
  closed: { title: 'Close this finding', confirmLabel: 'Close finding', noteLabel: 'Closed' },
  open: { title: 'Reopen this finding', confirmLabel: 'Reopen', noteLabel: 'Reopened' },
};

type RiskAcceptanceRecord = { reason: string; review_at: string; accepted_by: string; accepted_at: string };
type TriageValues = { assignee: string; notes: string };
type AuditHistoryState = { state: 'idle' | 'loading' | 'ready' | 'error'; items: DataItem[]; error: string };

function formatDay(value: unknown) {
  if (!value) return 'Not recorded';
  const date = new Date(String(value));
  if (Number.isNaN(date.getTime())) return String(value);
  return date.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
}

function readRiskAcceptance(entity: DataItem): RiskAcceptanceRecord | null {
  const value = entity.risk_acceptance;
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  const record = value as DataItem;
  return {
    reason: getString(record, ['reason'], ''),
    review_at: getString(record, ['review_at'], ''),
    accepted_by: getString(record, ['accepted_by'], ''),
    accepted_at: getString(record, ['accepted_at'], ''),
  };
}

/** Recorded target verification: verification_state, then a verification object's state, then a plain string. */
function targetVerificationState(item: DataItem) {
  const direct = getString(item, ['verification_state'], '');
  if (direct) return direct;
  const verification = item.verification;
  if (verification && typeof verification === 'object' && !Array.isArray(verification)) return getString(verification as DataItem, ['state'], '');
  return typeof verification === 'string' ? verification.trim() : '';
}

/** Describe progress only from persisted finding/remediation facts; no unsupported status mutation is implied. */
function buildFindingDecisionSteps(status: string, owner: string, remState: string, hasPlaybook: boolean, riskReviewAt = ''): FindingDecisionStep[] {
  const normalizedStatus = status.trim().toLowerCase();
  const normalizedOwner = owner.trim().toLowerCase();
  const ownerAssigned = Boolean(normalizedOwner && normalizedOwner !== 'unassigned' && normalizedOwner !== 'not reported');
  const decisionRecorded = DECISION_STATUSES.includes(normalizedStatus);
  const decisionMeta = normalizedStatus === 'accepted_risk'
    ? (riskReviewAt ? `Risk accepted, review by ${formatDay(riskReviewAt)}` : 'Risk accepted')
    : FINDING_STATUS_LABELS[normalizedStatus as FindingStatus] ?? formatFindingLabel(status);
  return [
    { id: 'opened', label: 'Finding opened', done: true, meta: `Recorded status: ${formatFindingLabel(status, 'Open')}` },
    { id: 'owned', label: 'Owner assigned', done: ownerAssigned, meta: ownerAssigned ? owner : 'No assignee recorded.' },
    ...(hasPlaybook ? [{ id: 'remediation', label: 'Remediation linked', done: true, meta: formatFindingLabel(remState, 'Playbook linked') }] : []),
    { id: 'decision', label: 'Decision recorded', done: decisionRecorded, meta: decisionRecorded ? decisionMeta : 'Accept risk, resolve, or mark false positive after review.' },
  ];
}

function formatFindingLabel(value: string, fallback = 'Not reported') {
  const trimmed = value.trim();
  if (!trimmed) return fallback;
  const label = trimmed.replace(/_/g, ' ');
  return label.charAt(0).toUpperCase() + label.slice(1);
}

function getString(item: DataItem | null | undefined, keys: string[], fallback = 'Not reported') {
  if (!item) return fallback;
  for (const key of keys) {
    const value = item[key];
    if (value !== undefined && value !== null && value !== '') return String(value);
  }
  return fallback;
}

/** Coerce an unknown API field into a list of object rows; returns null when the field is absent/not an array. */
function coerceItemArray(value: unknown): DataItem[] | null {
  if (!Array.isArray(value)) return null;
  return value.filter((row): row is DataItem => Boolean(row) && typeof row === 'object' && !Array.isArray(row));
}

/** Humanize a byte count for the evidence-bundle Size column (matches the prototype's KB/MB display). */
function formatBytes(value: unknown): string {
  const bytes = Number(value);
  if (!Number.isFinite(bytes) || bytes <= 0) return 'Not reported';
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

/** Map the finding's `remStateClass` (badge--warn/--danger/--muted/--success, §7.6) to a Badge tone. */
function remStateTone(remStateClass: string, remState: string): StatTone {
  const cls = remStateClass.trim().toLowerCase();
  if (cls.includes('danger')) return 'danger';
  if (cls.includes('warn')) return 'warn';
  if (cls.includes('success')) return 'success';
  if (cls.includes('muted')) return 'muted';
  if (cls.includes('info')) return 'muted';
  const state = remState.trim().toLowerCase();
  if (['resolved', 'delivered', 'fix_verified'].includes(state)) return 'success';
  if (state === 'accepted_risk') return 'muted';
  if (state === 'in_progress') return 'warn';
  if (['open', 'remediation_pending'].includes(state)) return 'warn';
  return 'default';
}

/**
 * Pointer convenience for artifact rows: a click on the row opens the same inspector as its View
 * button. The row is not a control itself (no role or tab stop), so the View button stays the only
 * keyboard and screen-reader target and nothing interactive is nested inside another control.
 */
function evidenceRowNavProps(artifactId: string, inspect: (artifactId: string) => void): Omit<HTMLAttributes<HTMLTableRowElement>, 'key'> {
  if (!artifactId) return {};
  return {
    className: 'finding-artifact-row',
    onClick: (event: ReactMouseEvent<HTMLTableRowElement>) => {
      if ((event.target as HTMLElement).closest('a, button, input, select, textarea, summary')) return;
      if (window.getSelection()?.toString()) return;
      inspect(artifactId);
    }
  };
}

function DetailStatusBanners({ loadError }: { loadError: string }) {
  return loadError ? <div className="form-banner error" role="alert">{loadError}</div> : null;
}

function ReadOnlyField({ label, field, children }: { label: string; field: string; children: ReactNode }) {
  return <div data-field={field}><span>{label}</span><strong>{children}</strong></div>;
}

export function FindingDetailView({
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
  ensureFindingDetailStyles();

  const { confirm, confirmWithReason } = useConfirmModal();
  const [busy, setBusy] = useState('');
  const [feedbackKey, setFeedbackKey] = useState(0);
  const [riskDialog, setRiskDialog] = useState<TriageValues | null>(null);
  const [decisionHistory, setDecisionHistory] = useState<AuditHistoryState>({ state: 'idle', items: [], error: '' });
  const [historyReloadToken, setHistoryReloadToken] = useState(0);
  const triageFormRef = useRef<HTMLFormElement | null>(null);
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');
  const [evidence, setEvidence] = useState<Awaited<ReturnType<typeof populateFindingEvidence>> | null>(null);
  const [evidenceReloadToken, setEvidenceReloadToken] = useState(0);
  const [affectedTargets, setAffectedTargets] = useState<DataItem[]>([]);
  const [affectedTargetsLoading, setAffectedTargetsLoading] = useState(true);
  const [affectedTargetsError, setAffectedTargetsError] = useState('');
  const [affectedTargetsReloadToken, setAffectedTargetsReloadToken] = useState(0);
  const [chainVerified, setChainVerified] = useState<boolean | null>(null);
  const [retestReview, setRetestReview] = useState(() => getRouteParam('retest') === 'review');
  const openInspector = useOpenInspector();
  const inspected = useInspectorRef();

  const remediation = readFindingRemediationFields(entity, data.wafActionItems);
  const canWriteFinding = sessionHasPermission(session, 'finding:write');
  const canAcceptRisk = sessionHasPermission(session, 'finding:accept_risk');
  const canReadAudit = sessionHasPermission(session, 'audit:read');
  const canStartFindingRetest = sessionHasPermission(session, 'test_run:start');
  const remSteps = remediation.remSteps.split('|').map((step) => step.trim()).filter(Boolean);
  const hasRemediationPlaybook = Boolean(
    remediation.remAction ||
    remediation.remDescription ||
    remediation.remSteps ||
    remediation.actionItemId
  );
  const title = plainFindingTitle(entity, [...data.targets, ...affectedTargets], data.checks);
  useEntityDocumentTitle(loading ? undefined : title);
  const slaDueAt = findingSlaDueAt(entity);
  const severity = getString(entity, ['severity'], 'unknown');
  const findingStatus = readFindingStatus(entity);
  const normalizedStatus = findingStatus.trim().toLowerCase();
  const riskAcceptance = readRiskAcceptance(entity);
  const systemSummary = getString(entity, ['system_summary'], '').trim();
  const humanNotes = getString(entity, ['notes'], '');
  const statusTransitions = findingStatusTransitions(normalizedStatus);
  const owner = getString(entity, ['assignee', 'rem_owner'], 'unassigned');
  const targetId = getString(entity, ['target_id'], '');
  const targetDisplay = targetId ? (getString(data.targets?.find((t) => t.id === targetId), ['value', 'hostname'], '') || getString(entity, ['target_hostname', 'target_value'], targetId)) : '';
  const testRunId = getString(entity, ['test_run_id'], '');
  const checkId = getString(entity, ['check_id'], '');
  const vectorFamily = getString(entity, ['vector_family', 'vector'], '');
  const lineage = readFindingLineage(entity);
  const originalRunId = lineage.originating?.testRunId || (testRunId === 'Not reported' ? '' : testRunId);
  const originalVerdictId = getString(entity, ['verdict_id'], '');
  const laterVerdictId = getString(entity, ['last_verdict_id'], '');
  const hasLaterVerdict = Boolean(laterVerdictId) && laterVerdictId !== originalVerdictId;
  const closedAt = lineage.closedAt || getString(entity, ['closed_at'], '');
  usePublishAssistantContext(entityId ? {
    route: 'finding-detail',
    entity: { type: 'finding', id: entityId },
    facts: {
      Finding: loading ? undefined : title,
      Severity: loading ? undefined : severity,
      Status: loading ? undefined : findingStatus,
      Target: targetDisplay || undefined,
      Check: checkId ? getString(data.checks?.find((check) => getString(check, ['check_id', 'id'], '') === checkId) ?? null, ['name', 'title'], checkId) : undefined,
      'Attack family': vectorFamily || undefined,
      'SLA due': slaDueAt || undefined,
      'Affected targets': affectedTargetsLoading ? undefined : affectedTargets.length,
      'Closed at': closedAt || undefined,
    },
  } : null);
  const closureBasis = fixVerifiedBasis(entity, decisionHistory.items);
  const retestAction = resolveFindingRetestAction(entity);
  const retestCheck = data.checks.find((check) => getString(check, ['check_id', 'id'], '') === checkId) ?? null;
  const retestBound = Number((retestCheck?.probe_profile as DataItem | undefined)?.max_requests);
  const retestTarget = [...data.targets, ...affectedTargets].find((target) => getString(target, ['id'], '') === targetId) ?? null;

  function inspectOriginal() {
    openInspector({ entry: 'finding', finding_id: entityId, target_id: targetId && targetId !== 'Not reported' ? targetId : undefined, check_id: checkId && checkId !== 'Not reported' ? checkId : undefined }, 'finding-view-evidence');
  }

  function inspectRun(runId: string) {
    openInspector({ entry: 'check_result', target_id: targetId || undefined, check_id: checkId || undefined, test_run_id: runId }, `lineage-${runId}`);
  }

  function inspectArtifact(artifactId: string) {
    openInspector({ entry: 'artifact', evidence_id: artifactId, finding_id: entityId }, `artifact-${artifactId}`);
  }

  function inspectSibling(siblingId: string, siblingTarget: string) {
    openInspector({ entry: 'finding', finding_id: siblingId, target_id: siblingTarget || undefined }, `sibling-${siblingId}`);
  }

  function closeRetestReview() {
    setRetestReview(false);
    replaceRouteParams({ retest: null });
  }

  const decisionSteps = buildFindingDecisionSteps(findingStatus, owner, remediation.remState, hasRemediationPlaybook, riskAcceptance?.review_at ?? '');
  // Every loaded finding that shares this finding's rule (same recorded outcome), this one included.
  // Rule siblings come from the server's exact check predicate across every status, read in pages.
  // A finding without a check id can only be compared with the loaded page, and says so.
  const ruleSource = useProgressiveFindings(config, session, { check_id: checkId }, 0, Boolean(checkId));
  const ruleRows = checkId ? ruleSource.items : (data.findings ?? []);
  const ruleComplete = checkId ? ruleSource.complete : data.findingsMeta ? !data.findingsMeta.hasMore : false;
  const ruleSiblings = useMemo(
    () => findingRuleSiblings(entity, ruleRows, data.targets ?? []),
    [entity, ruleRows, data.targets]
  );
  const ruleTitle = findingRuleTitle(entity, data.checks);
  const ruleAssetsRef = useRef<HTMLElement | null>(null);
  const ruleActiveCount = ruleSiblings.filter((item) => findingStatusBucket(item) === 'open').length;
  const ruleAssetCount = countFindingAssets(ruleSiblings, data.targets ?? []);
  const ruleHasSiblings = ruleSiblings.length > 1;
  const findingsListError = data.loadErrors?.findings ?? '';


  // A grouped queue row opens #finding-detail?id=...&focus=rule-assets; bring the asset list into view.
  useEffect(() => {
    if (loading) return;
    const query = window.location.hash.split('?')[1] ?? '';
    if (new URLSearchParams(query).get('focus') !== FINDING_RULE_ASSETS_FOCUS) return;
    const node = ruleAssetsRef.current;
    if (!node) return;
    const reduceMotion = window.matchMedia?.('(prefers-reduced-motion: reduce)').matches ?? false;
    const frame = window.requestAnimationFrame(() => {
      node.scrollIntoView({ behavior: reduceMotion ? 'auto' : 'smooth', block: 'start' });
      node.focus({ preventScroll: true });
    });
    return () => window.cancelAnimationFrame(frame);
  }, [entityId, loading]);

  useEffect(() => {
    let cancelled = false;
    setEvidence(null);
    setChainVerified(null);
    populateFindingEvidence(config, session, entityId).then((payload) => {
      if (!cancelled) setEvidence(payload);
    });
    return () => { cancelled = true; };
  }, [config, session, entityId, evidenceReloadToken]);

  useEffect(() => {
    let cancelled = false;
    setAffectedTargets([]);
    setAffectedTargetsError('');
    // Primary source per §4.6.3: affected targets embedded on the finding payload
    // (GET /v1/findings/:id, passed in as `entity`). Prefer `affected_targets`, then `targets`.
    const embedded = coerceItemArray(entity.affected_targets) ?? coerceItemArray(entity.targets);
    if (embedded && embedded.length > 0) {
      setAffectedTargets(embedded);
      setAffectedTargetsLoading(false);
      return undefined;
    }
    // Missing embedded context can be read only from the finding's exact declared target.
    const targetId = getString(entity, ['target_id'], '');
    if (!targetId) { setAffectedTargetsLoading(false); return undefined; }
    setAffectedTargetsLoading(true);
    requestJson(config, session, `/v1/targets/${encodeURIComponent(targetId)}`)
      .then((payload) => {
        if (cancelled) return;
        const record = (payload ?? {}) as DataItem;
        const target = record.target as DataItem | undefined;
        const verification = record.verification && typeof record.verification === 'object' && !Array.isArray(record.verification)
          ? record.verification as DataItem
          : null;
        if (!target || getString(target, ['id'], '') !== targetId) {
          setAffectedTargets([]);
          return;
        }
        const verificationState = getString(verification, ['state'], getString(target, ['verification_state'], ''));
        setAffectedTargets([{
          ...target,
          verification_state: verificationState,
          verification_title: resolveTargetVerificationProvenance(target, verification)
        }]);
      })
      .catch((err) => {
        if (!cancelled) setAffectedTargetsError(err instanceof Error ? err.message : 'Could not load affected targets.');
      })
      .finally(() => {
        if (!cancelled) setAffectedTargetsLoading(false);
      });
    return () => { cancelled = true; };
  }, [config, session, entityId, entity, affectedTargetsReloadToken]);

  useEffect(() => {
    if (!canReadAudit) {
      setDecisionHistory({ state: 'idle', items: [], error: '' });
      return undefined;
    }
    let cancelled = false;
    setDecisionHistory((current) => ({ ...current, state: 'loading', error: '' }));
    requestJson(config, session, `/v1/audit-log?resource=${encodeURIComponent(entityId)}&limit=50`)
      .then((payload) => {
        if (cancelled) return;
        const items = coerceItemArray((payload as DataItem | null)?.items) ?? [];
        const stamp = (item: DataItem) => Date.parse(getString(item, ['ts', 'created_at', 'at'], '')) || 0;
        setDecisionHistory({ state: 'ready', items: [...items].sort((left, right) => stamp(right) - stamp(left)), error: '' });
      })
      .catch((err) => {
        if (!cancelled) setDecisionHistory({ state: 'error', items: [], error: apiErrorMessage(err, 'Decision history could not load.') });
      });
    return () => { cancelled = true; };
  }, [config, session, entityId, canReadAudit, historyReloadToken]);

  function reportError(text: string) {
    setMessage('');
    setError(text);
    setFeedbackKey((value) => value + 1);
  }

  async function runAction(label: string, action: () => Promise<unknown>, success: string, onSuccess?: () => void) {
    setBusy(label);
    setError('');
    setMessage('');
    try {
      await action();
      setMessage(success);
      setFeedbackKey((value) => value + 1);
      onSuccess?.();
      await onRefresh();
    } catch (err) {
      reportError(apiErrorMessage(err, 'Action failed.'));
    } finally {
      setBusy('');
    }
  }

  async function patchFinding(body: Record<string, unknown>, success: string, action = 'update', onSuccess?: () => void) {
    if (!canWriteFinding) return;
    await runAction(
      `finding-${action}-${entityId}`,
      () => requestJson(config, session, `/v1/findings/${entityId}`, { method: 'PATCH', body }),
      success,
      () => {
        setHistoryReloadToken((value) => value + 1);
        onSuccess?.();
      }
    );
  }

  /** Assignee and notes as typed in the triage form, read before any dialog awaits so nothing typed is lost. */
  function readTriageValues(form: HTMLFormElement | null): TriageValues {
    const source = form ?? triageFormRef.current;
    if (!source) return { assignee: getString(entity, ['assignee'], ''), notes: humanNotes };
    const values = new FormData(source);
    return { assignee: String(values.get('assignee') ?? '').trim(), notes: String(values.get('notes') ?? '').trim() };
  }

  function retestContext(): ReactNode {
    const latest = lineage.latest;
    if (!latest || latest.pending || latest.finalized !== true) return null;
    return <p className="muted small">Most recent retest: <span className="mono">{latest.testRunId}</span>, finished {latest.completedAt ? formatTimestamp(latest.completedAt) : 'at an unrecorded time'}.</p>;
  }

  async function changeStatus(next: FindingStatus, form: HTMLFormElement | null) {
    if (!canWriteFinding) return;
    const triage = readTriageValues(form);
    const label = FINDING_STATUS_LABELS[next];
    if (next === 'accepted_risk') {
      if (!canAcceptRisk) return;
      setRiskDialog(triage);
      return;
    }
    if (next === 'in_progress') {
      const accepted = await confirm({
        title: 'Start work on this finding',
        description: 'Mark this finding as in progress? Its severity SLA clock keeps running until it is resolved, closed, marked a false positive, or risk-accepted.',
        confirmLabel: 'Start work',
        confirmTone: 'default'
      });
      if (!accepted) return;
      await patchFinding({ status: next, assignee: triage.assignee, notes: triage.notes }, 'Finding marked in progress.', `status-${next}`);
      return;
    }
    const outcome = REASONED_OUTCOMES[next];
    if (!outcome) return;
    const closing = CLOSED_OUTCOMES.includes(next);
    const reason = await confirmWithReason({
      title: outcome.title,
      description: (
        <div className="stack-tight">
          <p>{FINDING_STATUS_DESCRIPTIONS[next]}.</p>
          {closing ? retestContext() : null}
          {closing
            ? <p>Closure is a recorded status change, not proof of a fix. Findings on other targets are not changed.</p>
            : <p>Reopening returns the finding to active work and restarts nothing on the target.</p>}
        </div>
      ),
      confirmLabel: outcome.confirmLabel,
      confirmTone: closing ? 'danger' : 'default',
      reason: { label: closing ? 'Reason for this outcome' : 'Reason for reopening', required: true, placeholder: 'Recorded with this decision in the triage notes.' }
    });
    if (!reason) return;
    await patchFinding(
      { status: next, assignee: triage.assignee, notes: findingDecisionNote(triage.notes, outcome.noteLabel, reason) },
      `Finding status changed to ${label.toLowerCase()}.`,
      `status-${next}`
    );
  }

  async function acceptRisk(input: RiskAcceptanceInput) {
    const triage = riskDialog ?? readTriageValues(null);
    await patchFinding(
      { status: 'accepted_risk', risk_acceptance: input, assignee: triage.assignee, notes: triage.notes },
      `Risk accepted. Review by ${formatDay(input.review_at)}.`,
      'status-accepted_risk',
      () => setRiskDialog(null)
    );
  }

  async function markDelivered() {
    if (!canWriteFinding) return;
    if (!remediation.actionItemId) {
      reportError('No remediation action item is linked to this finding.');
      return;
    }
    await runAction(`deliver-${entityId}`, () => requestJson(config, session, `/v1/waf/action-items/${encodeURIComponent(remediation.actionItemId)}/deliver`, { method: 'POST' }), 'Remediation marked delivered.');
  }

  async function verifyChain() {
    setChainVerified(null);
    await runAction(`verify-${entityId}`, async () => {
      // The verify endpoint recomputes the SHA-256 over the export payload and compares it to
      // the custody manifest digest, so it needs { payload, custody }, not { finding_id }.
      // The finding export is the canonical producer of that bound pair ({ ...payload, custody }).
      const exported = await requestJson(config, session, `/v1/findings/${entityId}/export`, { method: 'POST' }) as DataItem | null;
      if (!exported || typeof exported !== 'object') {
        throw new Error('Evidence export payload unavailable for verification.');
      }
      const { custody, ...payload } = exported;
      if (!custody || typeof custody !== 'object') {
        throw new Error('Custody manifest missing from evidence export.');
      }
      const verifyUrl = evidence?.verify_url ?? '/v1/custody/verify';
      const result = await requestJson(config, session, verifyUrl, { method: 'POST', body: { payload, custody } }) as DataItem | null;
      // The endpoint returns HTTP 200 even when verification fails, so inspect result.ok explicitly.
      if (!result || result.ok !== true) {
        setChainVerified(false);
        const verification = (result && typeof result.verification === 'object' ? result.verification : {}) as DataItem;
        const reason = getString(verification, ['error'], 'verification_failed');
        throw new Error(`Custody verification failed: ${formatFindingLabel(reason)}.`);
      }
      setChainVerified(true);
    }, 'Custody chain verified. The SHA-256 digest matches the sealed manifest.');
  }

  async function exportBundle() {
    // The export endpoint returns the sealed bundle synchronously (payload + custody manifest);
    // there is no queued job, so hand the file to the operator instead of discarding it.
    await runAction(`export-${entityId}`, async () => {
      const bundle = await requestJson(config, session, `/v1/findings/${encodeURIComponent(entityId)}/export`, { method: 'POST' });
      triggerJsonDownload(`finding-${entityId}-evidence.json`, bundle);
    }, 'Evidence bundle downloaded with its SHA-256 custody manifest.');
  }

  const affectedColumns: TableColumn<DataItem>[] = [
    {
      key: 'target',
      label: 'Target',
      render: (item) => <a
        className="detail-entity-link"
        href={buildDetailHref('target-detail', getString(item, ['id'], ''))}
        aria-label={`Open target ${getString(item, ['value', 'id'], 'target')}`}
      >{getString(item, ['value', 'id'], '')}</a>
    },
    { key: 'kind', label: 'Kind', render: (item) => plainCodeLabel(getString(item, ['kind'], ''), 'Not reported') },
    { key: 'value', label: 'Value', render: (item) => <span className="mono">{getString(item, ['value'], 'Not reported')}</span> },
    {
      key: 'verification',
      label: 'Verification',
      render: (item) => {
        const state = targetVerificationState(item);
        if (!state) {
          const id = getString(item, ['id'], '');
          return id
            ? <a className="detail-entity-link muted" href={buildDetailHref('target-detail', id)} aria-label={`Verification not reported; open target ${getString(item, ['value', 'id'], id)}`}>Not reported</a>
            : <span className="muted">Not reported</span>;
        }
        return <VerifyChip state={state} provenance={getString(item, ['verification_title'], 'Recorded target verification state.')} />;
      }
    },
    { key: 'eligibility', label: 'Eligibility', render: (item) => plainCodeLabel(getString(item, ['eligibility'], ''), 'Not reported') },
    { key: 'verdict', label: 'Last verdict', render: (item) => { const verdict = getString(item, ['last_verdict'], ''); return verdict ? plainVerdictLabel(verdict) : <span className="muted">Not reported</span>; } }
  ];

  const ruleAssetColumns: TableColumn<DataItem>[] = [
    {
      key: 'asset',
      label: 'Target',
      render: (item) => {
        const siblingId = getString(item, ['id'], '');
        const label = findingAssetLabel(item, data.targets);
        if (siblingId === entityId) {
          return <span className="rule-asset-current"><strong>{label}</strong><small>This finding</small></span>;
        }
        return siblingId ? (
          <a className="rule-asset-link" href={buildDetailHref('finding-detail', siblingId)} aria-label={`Open finding on ${label}`}>
            <strong>{label}</strong>
            <small className="mono">{siblingId}</small>
          </a>
        ) : <span className="mono">{label}</span>;
      }
    },
    {
      key: 'check',
      label: 'Check',
      render: (item) => {
        const itemCheckId = getString(item, ['check_id', 'check'], '');
        if (!itemCheckId) return <span className="rule-asset-meta">Not reported</span>;
        const itemCheck = data.checks.find((check) => getString(check, ['check_id', 'id'], '') === itemCheckId);
        return <span className="rule-asset-stack"><span>{checkPresentation(itemCheckId).name}</span><small className="mono">{itemCheckId}</small></span>;
      }
    },
    {
      key: 'status',
      label: 'Status',
      render: (item) => {
        const status = readFindingStatus(item);
        return <Badge tone={findingStatusTone(status)}>{formatFindingLabel(status)}</Badge>;
      }
    },
    {
      key: 'severity',
      label: 'Severity',
      render: (item) => {
        const value = getString(item, ['severity'], 'unknown');
        return <Badge tone={severityTone(value)}>{formatSeverityLabel(value)}</Badge>;
      }
    },
    {
      key: 'observed',
      label: 'Observed',
      render: (item) => {
        const observed = findingObservedAt(item) ?? findingOpenedAt(item);
        return observed !== null
          ? <span className="rule-asset-stack"><span>{findingObservationLabel(item)}</span><small>{formatDate(observed)}</small></span>
          : <span className="rule-asset-meta">Not reported</span>;
      }
    },
    {
      key: 'evidence',
      label: 'Evidence',
      render: (item) => {
        const siblingId = getString(item, ['id'], '');
        const evidenceCount = Array.isArray(item.evidence_ids) ? item.evidence_ids.filter(Boolean).length : 0;
        if (!siblingId) return <span className="rule-asset-evidence-missing">No finding ID recorded</span>;
        return (
          <Button
            size="sm"
            variant="ghost"
            data-focus-key={`sibling-${siblingId}`}
            aria-label={`View the original evidence for the finding on ${findingAssetLabel(item, data.targets)}`}
            onClick={() => inspectSibling(siblingId, getString(item, ['target_id'], ''))}
          >
            <Eye size={14} aria-hidden="true" />
            {evidenceCount ? `View ${evidenceCount} record${evidenceCount === 1 ? '' : 's'}` : 'View evidence'}
          </Button>
        );
      }
    }
  ];

  const artifactColumns: TableColumn<DataItem>[] = [
    {
      key: 'artifact',
      label: 'Artifact',
      render: (item) => {
        const artifactId = getString(item, ['id'], '');
        const label = plainCodeLabel(getString(item, ['kind'], ''), 'Evidence artifact');
        const cited = Array.isArray(entity.evidence_ids) && entity.evidence_ids.map(String).includes(artifactId);
        return (
          <span className="entity-cell-stack">
            <span>{label}</span>
            {artifactId ? null : <small>No artifact ID recorded</small>}
            <small>{cited ? 'Cited by this finding' : 'Recorded for the originating run'}</small>
          </span>
        );
      }
    },
    { key: 'kind', label: 'Kind', render: (item) => plainCodeLabel(getString(item, ['kind'], ''), 'Not reported') },
    {
      key: 'run',
      label: 'Run',
      render: (item) => {
        const runId = getString(item, ['run_id'], '');
        return runId ? <a className="detail-entity-link mono" href={buildDetailHref('run-detail', runId)}>{runId}</a> : <span className="rule-asset-meta">Not reported</span>;
      }
    },
    { key: 'sha', label: 'Recorded digest', render: (item) => <span className="mono small finding-digest" title={getString(item, ['sha256', 'content_sha256'], 'Not reported')}>{getString(item, ['sha256', 'content_sha256'], 'Not reported')}</span> },
    { key: 'sealed', label: 'Sealed', render: (item) => formatTimestamp(item.sealed_at) },
    { key: 'size', label: 'Size', render: (item) => <span className="num">{formatBytes(item.size_bytes)}</span> },
    {
      key: 'inspect',
      label: 'Inspect',
      render: (item) => {
        const artifactId = getString(item, ['id'], '');
        return artifactId ? (
          <Button size="sm" variant="ghost" data-focus-key={`artifact-${artifactId}`} onClick={(event) => { event.stopPropagation(); inspectArtifact(artifactId); }} aria-label={`View artifact ${artifactId} in the evidence inspector`}>
            <Eye size={14} aria-hidden="true" />View
          </Button>
        ) : null;
      }
    }
  ];

  const custodyChain = evidence?.custody_chain ?? [];
  const bundleSha256 = getString(evidence?.bundle, ['sha256'], '');
  const custodySealedAt = getString(evidence?.bundle, ['sealed_at'], '');
  const custodyStatus = chainVerified === true ? 'Verified' : chainVerified === false ? 'Verification failed' : 'Not checked';
  const custodyYaml = [
    `finding: ${entityId}`,
    `digest_kind: ${getString(evidence?.bundle, ['custody_schema_version'], 'json-key-sorted-v1')}`,
    ...(custodyChain.length
      ? ['chain:', ...custodyChain.flatMap((step) => [
          `  - artifact: ${getString(step, ['kind', 'step'], 'artifact')}`,
          `    sha256: ${getString(step, ['sha256'], 'not_recorded')}`
        ])]
      : []),
    `bundle_sha256: ${bundleSha256 || 'not_recorded'}`,
    ...(custodySealedAt ? [`sealed_at: ${custodySealedAt}`] : []),
    `verified: ${chainVerified === null ? 'not_checked' : chainVerified}`
  ].join('\n');

  return (
    <div className="content finding-detail-page" aria-busy={loading || undefined}>
      <DetailBackLink route="finding-detail" />
      <div className="page-head">
        <div className="finding-title-copy">
          <h1 className="page-title">{title}</h1>
          <p className="muted mono finding-id">{entityId}</p>
          <div className="detail-status-line">
            <Badge tone={severityTone(severity)} title={`Recorded severity: ${formatSeverityLabel(severity)}`}>{formatSeverityLabel(severity)}</Badge>
            <FindingStatusBadge status={findingStatus} title={`Recorded status: ${formatFindingLabel(findingStatus)}`} />
          </div>
        </div>
        <div className="row-actions">
          <Button size="sm" variant="default" data-focus-key="finding-view-evidence" onClick={inspectOriginal}><Eye size={14} aria-hidden="true" />View original evidence</Button>
          <AskAiButton
            config={config}
            session={session}
            context={{ finding_id: entityId, ...(targetId && targetId !== 'Not reported' ? { target_id: targetId } : {}), label: title }}
          />
        </div>
      </div>

      {loading ? <PortalLoadingSkeleton rows={2} /> : null}
      <DetailStatusBanners loadError={loadError} />
      {error ? <Toast key={`finding-error-${feedbackKey}`} message={error} tone="error" duration={0} onDismiss={() => setError('')} /> : null}
      {message && !error ? <Toast key={`finding-message-${feedbackKey}`} message={message} tone="success" duration={5000} onDismiss={() => setMessage('')} /> : null}

      {!loading ? (
        <>
      <MissingControlCard key={entityId} finding={entity} />
      <Card className="finding-summary-card">
        <CardHeader>
          <div><CardTitle>Finding summary</CardTitle><CardDescription>Key facts and exact relationships for triage and evidence review.</CardDescription></div>
        </CardHeader>
        <CardContent>
          <dl className="finding-summary-facts">
            <div className="finding-summary-fact"><dt>SLA due</dt><dd>{slaDueAt ? formatDate(slaDueAt) : 'Not reported'}{isFindingSlaBreach(entity) ? ' · breached' : ''}</dd></div>
            {checkId ? <div className="finding-summary-fact"><dt>Check</dt><dd><span>{checkPresentation(checkId).name}</span><small className="mono">{checkId}</small></dd></div> : null}
            {vectorFamily ? <div className="finding-summary-fact"><dt>Vector</dt><dd>{formatFindingLabel(vectorFamily)}</dd></div> : null}
            {targetId ? <div className="finding-summary-fact"><dt>Target ID</dt><dd className="mono">{targetId}</dd></div> : null}
            {entity.created_at ? <div className="finding-summary-fact"><dt>Opened</dt><dd>{formatDate(entity.created_at)}</dd></div> : null}
            {entity.updated_at ? <div className="finding-summary-fact"><dt>Updated</dt><dd>{formatDate(entity.updated_at)}</dd></div> : null}
          </dl>
          {targetId ? (
            <div className="finding-relations">
              <AnchorButton size="sm" variant="secondary" href={buildDetailHref('target-detail', targetId)}>Open target {targetDisplay}</AnchorButton>
            </div>
          ) : null}
          <section className="finding-lineage" aria-label="Original evidence and later results">
            <div className="finding-lineage-item">
              <span className="finding-lineage-label">Original evidence</span>
              <span>{originalRunId ? <>Recorded execution <a className="detail-entity-link mono" href={buildDetailHref('run-detail', originalRunId)}>{originalRunId}</a></> : 'Originating execution not recorded'}{originalVerdictId ? <> · verdict <span className="mono">{originalVerdictId}</span></> : null}</span>
              <span className="muted small">The observation that opened this finding. It is kept even after later results.</span>
            </div>
            <div className="finding-lineage-item">
              <span className="finding-lineage-label">Retests of this finding</span>
              {lineage.retests.length ? (
                <ul className="finding-lineage-runs">
                  {lineage.retests.map((run) => (
                    <li key={run.testRunId}>
                      <Button size="sm" variant="ghost" className="mono" data-focus-key={`lineage-${run.testRunId}`} aria-label={`View result of retest run ${run.testRunId}`} onClick={() => inspectRun(run.testRunId)}>{run.testRunId}</Button>
                      {run.createdAt ? <span className="muted small"> requested {formatDate(run.createdAt)}</span> : null}
                      {lineage.latest?.testRunId === run.testRunId ? (
                        <>
                          <Badge tone="muted">Most recent retest</Badge>
                          <span className="muted small">
                            {lineage.latest.pending || lineage.latest.finalized === false
                              ? `Not finished${lineage.latest.status ? ` (${lineage.latest.status.replace(/_/g, ' ')})` : ''}; no later result yet`
                              : lineage.latest.finalized ? `Finished${lineage.latest.completedAt ? ` ${formatDate(lineage.latest.completedAt)}` : ''}` : ''}
                          </span>
                        </>
                      ) : null}
                    </li>
                  ))}
                </ul>
              ) : <span className="muted">No run has been recorded as a retest of this finding.</span>}
              <span className="muted small">Only runs started from Review retest are retests. A retest result does not close this finding or any other.</span>
            </div>
            <div className="finding-lineage-item">
              <span className="finding-lineage-label">Later runs, same target and check</span>
              {lineage.laterSamePair.length ? (
                <ul className="finding-lineage-runs">
                  {lineage.laterSamePair.map((run) => (
                    <li key={run.testRunId}>
                      <Button size="sm" variant="ghost" className="mono" data-focus-key={`lineage-${run.testRunId}`} aria-label={`View result of run ${run.testRunId}`} onClick={() => inspectRun(run.testRunId)}>{run.testRunId}</Button>
                      <span className="muted small">{run.finalized === false ? ' not finished' : run.finalized ? ' finished' : ''}</span>
                    </li>
                  ))}
                </ul>
              ) : <span className="muted">No other run of this target and check is recorded.</span>}
              <span className="muted small">Routine runs without retest intent. They are listed for context and do not change this finding.</span>
              {hasLaterVerdict ? <span className="small">Latest verdict recorded on this finding: <span className="mono">{laterVerdictId}</span></span> : null}
            </div>
            <div className="finding-lineage-item">
              <span className="finding-lineage-label">Closure</span>
              {normalizedStatus === 'accepted_risk' ? (
                <>
                  <span>
                    Risk accepted{riskAcceptance?.accepted_by ? <> by <span className="mono">{riskAcceptance.accepted_by}</span></> : ''}
                    {riskAcceptance?.accepted_at ? ` on ${formatDay(riskAcceptance.accepted_at)}` : ''}
                    {riskAcceptance?.review_at ? `, review by ${formatDay(riskAcceptance.review_at)}` : ''}
                    {riskAcceptance ? '' : ' (no reason or review date recorded)'}
                  </span>
                  {riskAcceptance?.reason ? <span className="finding-risk-reason">{riskAcceptance.reason}</span> : null}
                </>
              ) : normalizedStatus === 'fix_verified' ? (
                <span className="finding-closure-basis" data-basis={closureBasis.basis || 'unknown'}>
                  <strong>{closureBasis.label}</strong>
                  <span>
                    {closedAt ? `Verified ${formatTimestamp(closedAt)}. ` : ''}
                    {closureBasis.basis === 'violation_not_reproduced'
                      ? 'A re-check from the same probe perspective took at least two agreeing samples, probed every declared port and did not reproduce the violation. Outside-in evidence cannot prove a port is denied, only that the recorded violation is gone.'
                      : closureBasis.basis === 'passing_retest'
                        ? 'A later passing check with the same scope and check version confirmed it.'
                        : `A later re-check with the same scope and check version confirmed it.${canReadAudit ? '' : ' Audit readers can see how it was verified in the decision history.'}`}
                    {getString(entity, ['verifying_run_id'], '') ? <> Verifying run <a className="detail-entity-link mono" href={buildDetailHref('run-detail', getString(entity, ['verifying_run_id'], ''))}>{getString(entity, ['verifying_run_id'], '')}</a>.</> : ' Verifying run not recorded.'}
                  </span>
                </span>
              ) : CLOSED_OUTCOMES.includes(normalizedStatus) ? (
                <span>
                  {closedAt ? `Closed ${formatTimestamp(closedAt)}` : 'Closed; closure time not recorded'}
                  {normalizedStatus === 'closed' ? '' : ` · ${FINDING_STATUS_LABELS[normalizedStatus as FindingStatus]}`}
                </span>
              ) : normalizedStatus === 'accepted' ? (
                <span>Accepted (older status set through the API){closedAt ? ` ${formatTimestamp(closedAt)}` : ''}</span>
              ) : <span className="muted">Not closed.</span>}
              <span className="muted small">{normalizedStatus === 'fix_verified' ? 'Fix verified is set only by AstraNull after a re-check confirms it. Reopen it if the gap comes back.' : 'Closure is a recorded status change, not proof of a fix.'} Findings on other targets are never closed with this one.</span>
            </div>
          </section>
        </CardContent>
      </Card>

      <div className="dash-grid">
        <Card className="finding-triage-card">
          <CardHeader>
            <CardTitle>Triage</CardTitle>
            <CardDescription>{canWriteFinding ? 'Assign an owner, record notes, and record a decision.' : 'Owner, notes, and recorded decision for this finding.'}</CardDescription>
          </CardHeader>
          <CardContent>
            <ol className="verify-ladder finding-decision-ladder" aria-label="Finding decision status">
              {decisionSteps.map((step, index) => {
                const now = !step.done && decisionSteps.slice(0, index).every((entry) => entry.done);
                return (
                  <li key={step.id} className={`vl-step${step.done ? ' is-done' : ''}${now ? ' is-now' : ''}`}>
                    <span className="vl-num" aria-hidden="true">{step.done ? <Check size={13} strokeWidth={2.6} /> : index + 1}</span>
                    <div className="vl-body"><strong>{step.label}</strong><span className="vl-meta">{step.meta}</span></div>
                  </li>
                );
              })}
            </ol>
            {systemSummary ? (
              <div className="finding-recorded-explanation">
                <span className="finding-triage-group-label">Recorded explanation</span>
                <p>{systemSummary}</p>
                <small>Written by the server from the verdict that opened this finding. It cannot be edited, and triage notes never replace it.</small>
              </div>
            ) : null}
            {canWriteFinding ? (
            <form
              key={`triage-${entityId}-${getString(entity, ['updated_at'], '')}`}
              ref={triageFormRef}
              className="product-form product-form--compact"
              onSubmit={(event) => {
                event.preventDefault();
                const triage = readTriageValues(event.currentTarget);
                void patchFinding({ assignee: triage.assignee, notes: triage.notes }, 'Triage saved.', 'triage');
              }}
            >
              <label className="full"><span>Assignee</span><input name="assignee" defaultValue={getString(entity, ['assignee'], '')} /></label>
              <label className="full"><span>Notes</span><textarea name="notes" rows={3} defaultValue={humanNotes} placeholder="Your team's triage notes. The recorded explanation above is kept separately." /></label>
              <div className="row-actions action-bar-compact full" role="group" aria-label="Triage actions">
                <Button type="submit" size="sm" variant="secondary" loading={busy === `finding-triage-${entityId}`} disabled={busy !== ''}>Save triage</Button>
                <Button size="sm" variant="secondary" disabled={busy !== '' || !canStartFindingRetest || !retestAction} title={!retestAction ? 'Retest details are missing from this finding.' : undefined} onClick={() => setRetestReview(true)}>Review retest</Button>
              </div>
              <div className="finding-decision-group full" role="group" aria-labelledby={`finding-decision-${entityId}`}>
                <p className="finding-triage-group-label" id={`finding-decision-${entityId}`}>Decision</p>
                <div className="finding-decision-current">
                  <span>Current status</span>
                  <FindingStatusBadge status={findingStatus} title={FINDING_STATUS_DESCRIPTIONS[normalizedStatus as FindingStatus] ?? `Recorded status: ${formatFindingLabel(findingStatus)}`} />
                </div>
                <div className="finding-decision-actions" role="group" aria-label="Change status">
                  {statusTransitions.map((transition) => {
                    const acceptBlocked = transition.status === 'accepted_risk' && !canAcceptRisk;
                    return (
                      <Button
                        key={transition.status}
                        size="sm"
                        variant="secondary"
                        className={transition.status === 'accepted_risk' ? 'finding-accept-risk-btn' : undefined}
                        title={acceptBlocked ? 'Accepting risk needs the owner or admin role.' : FINDING_STATUS_DESCRIPTIONS[transition.status]}
                        aria-describedby={acceptBlocked ? `finding-accept-note-${entityId}` : undefined}
                        loading={busy === `finding-status-${transition.status}-${entityId}`}
                        disabled={busy !== '' || acceptBlocked}
                        onClick={(event) => {
                          const form = event.currentTarget.form;
                          void changeStatus(transition.status, form);
                        }}
                      >
                        {transition.status === 'accepted_risk' ? 'Accept risk…' : transition.label}
                      </Button>
                    );
                  })}
                </div>
                {statusTransitions.some((transition) => transition.status === 'accepted_risk') && !canAcceptRisk ? (
                  <p className="muted small" id={`finding-accept-note-${entityId}`}>Accepting risk needs the owner or admin role. Ask one of them to record the decision.</p>
                ) : null}
              </div>
            </form>
            ) : (
              <>
                <div className="kv-list finding-triage-readonly">
                  <ReadOnlyField label="Status" field="status">{FINDING_STATUS_LABELS[normalizedStatus as FindingStatus] ?? formatFindingLabel(findingStatus)}</ReadOnlyField>
                  <ReadOnlyField label="Assignee" field="assignee">{getString(entity, ['assignee'], 'Unassigned')}</ReadOnlyField>
                  <ReadOnlyField label="Notes" field="notes"><span className="finding-notes-value">{humanNotes.trim() || 'No triage notes recorded.'}</span></ReadOnlyField>
                  <ReadOnlyField label="Decided" field="decided">{closedAt ? formatTimestamp(closedAt) : 'No decision recorded'}</ReadOnlyField>
                  {riskAcceptance ? (
                    <ReadOnlyField label="Risk acceptance" field="risk-acceptance">
                      <span className="finding-notes-value">
                        {riskAcceptance.reason || 'No reason recorded'}
                        {riskAcceptance.accepted_by ? ` · accepted by ${riskAcceptance.accepted_by}` : ''}
                        {riskAcceptance.review_at ? ` · review by ${formatDay(riskAcceptance.review_at)}` : ''}
                      </span>
                    </ReadOnlyField>
                  ) : null}
                  <ReadOnlyField label="Last updated" field="updated">{entity.updated_at ? formatTimestamp(entity.updated_at) : 'Not recorded'}</ReadOnlyField>
                </div>
                <p className="muted small" data-role-restricted="true">Finding triage is read-only for your role. Changes need finding:write.</p>
              </>
            )}
            <section className="finding-decision-history" aria-labelledby={`finding-history-${entityId}`}>
              <h3 id={`finding-history-${entityId}`}>Decision history</h3>
              {!canReadAudit ? (
                <p className="muted small">Decision history is visible to audit readers.</p>
              ) : decisionHistory.state === 'loading' && decisionHistory.items.length === 0 ? (
                <p className="muted small" role="status">Loading decision history…</p>
              ) : decisionHistory.state === 'error' ? (
                <div className="form-banner error" role="alert">
                  Decision history could not load: {decisionHistory.error}{' '}
                  <Button size="sm" variant="ghost" onClick={() => setHistoryReloadToken((value) => value + 1)}>Retry</Button>
                </div>
              ) : decisionHistory.items.length === 0 ? (
                <p className="muted small">No decisions recorded yet.</p>
              ) : (
                <ol aria-label="Recorded decisions, newest first">
                  {decisionHistory.items.map((item, index) => {
                    const eventId = getString(item, ['id'], '');
                    const metadata = item.metadata && typeof item.metadata === 'object' && !Array.isArray(item.metadata) ? item.metadata as DataItem : null;
                    const notes = getString(metadata, ['notes'], '').trim();
                    const riskRecord = metadata?.risk_acceptance && typeof metadata.risk_acceptance === 'object' ? metadata.risk_acceptance as DataItem : null;
                    const riskReason = getString(riskRecord, ['reason'], '').trim();
                    const actor = getString(item, ['actor_user_id'], 'Unknown actor');
                    const role = getString(item, ['actor_role'], '');
                    return (
                      <li key={eventId || `history-${index}`}>
                        <strong>{formatAuditAction(getString(item, ['action'], ''), 'Recorded change', metadata ?? undefined)}</strong>
                        <span className="finding-history-meta">
                          {formatTimestamp(getString(item, ['ts', 'created_at', 'at'], ''))} · <span className="mono">{actor}</span>{role ? ` (${formatFindingLabel(role)})` : ''}
                        </span>
                        {riskReason ? <span className="finding-history-notes">Risk reason: {riskReason}</span> : null}
                        {notes ? <span className="finding-history-notes">Notes: {notes}</span> : null}
                        {eventId ? <a className="detail-entity-link small" href={`#audit?event=${encodeURIComponent(eventId)}`}>View in audit log</a> : null}
                      </li>
                    );
                  })}
                </ol>
              )}
            </section>
            <ConfirmModal
              open={retestReview && canStartFindingRetest && Boolean(retestAction)}
              title="Review this retest"
              description={(
                <div className="stack-tight scan-review">
                  <dl className="td-review-list">
                    <div><dt>Finding</dt><dd>{title} <span className="mono">{entityId}</span></dd></div>
                    <div><dt>Target</dt><dd className="mono">{getString(retestTarget, ['value'], targetId || 'Not recorded')}</dd></div>
                    <div><dt>Check</dt><dd>{checkId ? checkPresentation(checkId).name : 'Not recorded'}</dd></div>
                    {retestAction?.kind === 'safe-run' ? <div><dt>Recorded as</dt><dd>Retest of this finding (same target and check)</dd></div> : null}
                    <div><dt>Upper bound</dt><dd>{retestAction?.kind === 'safe-run' ? (Number.isFinite(retestBound) ? `${retestBound} requests` : 'Not recorded in the catalog') : retestAction?.kind === 'waf-validation' ? 'WAF marker validation for the linked asset' : 'CVE pipeline retest'}</dd></div>
                  </dl>
                  <p>This starts a new bounded check on the same target and check. The server re-checks ownership, safe windows, rate, concurrency and kill-switch gates now; an expired scope is not replayed.</p>
                  <p>The original evidence stays. A passing retest is shown as a later result and never closes other domains.</p>
                </div>
              )}
              confirmLabel="Start retest"
              confirmTone="default"
              busy={busy === `retest-${entityId}`}
              onCancel={closeRetestReview}
              onConfirm={() => void runAction(`retest-${entityId}`, async () => {
                  const retest = retestAction;
                  if (!retest) throw new Error('Retest details are missing from this finding.');
                  // Every kind resolveFindingRetestAction can return must dispatch a real
                  // request; otherwise runAction reports a false "Retest started." success.
                  // Mirrors retestFinding() in detail-pages.tsx.
                  if (retest.kind === 'waf-validation') {
                    await requestJson(config, session, '/v1/waf/validations', { method: 'POST', body: { waf_asset_id: retest.wafAssetId, modes: ['marker'] } });
                  } else if (retest.kind === 'cve-retest') {
                    await requestJson(config, session, `/v1/waf/cve-pipeline/${encodeURIComponent(retest.pipelineId)}/retest`, { method: 'POST' });
                  } else if (retest.kind === 'cve-retest-url') {
                    await requestJson(config, session, retest.retestUrl, { method: 'POST' });
                  } else if (retest.kind === 'safe-run') {
                    if (!targetId) throw new Error('This finding has no declared target, so a retest cannot be recorded against it.');
                    await requestJson(config, session, '/v1/test-runs', { method: 'POST', body: { check_id: retest.checkId, target_id: targetId, retest_of_finding_id: entityId } });
                  } else {
                    throw new Error('Unsupported retest kind for this finding.');
                  }
                  closeRetestReview();
                }, 'Retest started. Its result appears as a later result; the original evidence is unchanged.')}
            />
            <RiskAcceptanceDialog
              open={Boolean(riskDialog) && canAcceptRisk}
              busy={busy === `finding-status-accepted_risk-${entityId}`}
              onCancel={() => setRiskDialog(null)}
              onConfirm={(input) => void acceptRisk(input)}
            />
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>Verdict explanation</CardTitle>
          </CardHeader>
          <CardContent>
            <FindingExplanationPanel finding={entity} config={config} session={session} />
            {testRunId ? <VerdictReplay config={config} session={session} runId={testRunId} /> : null}
          </CardContent>
        </Card>
      </div>

      <FindingDetectionHistory
        entity={entity}
        entityId={entityId}
        targetId={targetId}
        targetDisplay={targetDisplay}
        checkId={checkId}
        checks={data.checks}
        dataFindings={data.findings}
        config={config}
        session={session}
        onInspectFinding={(finding) => {
          const id = getString(finding, ['id'], '');
          if (!id) return;
          openInspector({ entry: 'finding', finding_id: id, target_id: targetId || undefined, check_id: getString(finding, ['check_id'], '') || undefined }, `finding-${id}`);
        }}
        onInspectRun={(runId, runCheckId) => {
          if (!runId) return;
          openInspector({ entry: 'check_result', target_id: targetId || undefined, check_id: runCheckId || checkId, test_run_id: runId }, `run-${runId}`);
        }}
      />

      <Card className="finding-affected-targets">
        <CardHeader>
          <div><CardTitle>Affected targets</CardTitle><CardDescription>Declared targets where this finding was recorded.</CardDescription></div>
        </CardHeader>
        <CardContent>
          {affectedTargetsLoading ? <PortalLoadingSkeleton rows={2} /> : affectedTargetsError ? (
            <EmptyState
              icon={TriangleAlert}
              title="Affected targets unavailable"
              body={`Could not load the recorded target: ${affectedTargetsError}`}
              actionLabel="Retry"
              onAction={() => setAffectedTargetsReloadToken((value) => value + 1)}
            />
          ) : affectedTargets.length === 0 ? (
            <EmptyState
              icon={TriangleAlert}
              title="No declared targets matched."
              body="This finding does not record a matching declared target. No affected domain is inferred."
            />
          ) : (
            <DataTable
              columns={affectedColumns}
              items={affectedTargets}
              getRowId={(item) => getString(item, ['id'], '')}
              empty={<span className="muted">No affected targets returned.</span>}
            />
          )}
        </CardContent>
      </Card>

      <section
        id="rule-assets"
        ref={ruleAssetsRef}
        tabIndex={-1}
        className="rule-assets-section"
        aria-labelledby="rule-assets-title"
      >
      <Card className="rule-assets-card">
        <CardHeader>
          <div>
            <CardTitle id="rule-assets-title">Other targets with this finding</CardTitle>
            <CardDescription>Other targets where &ldquo;{ruleTitle}&rdquo; was recorded. Open one to see its own evidence and fix.</CardDescription>
          </div>
        </CardHeader>
        <CardContent>
          {findingsListError ? (
            <div className="form-banner error" role="alert">
              Could not load the finding list, so other targets with this finding may be missing: {findingsListError}
            </div>
          ) : null}

          <p className="rule-assets-summary">
            {ruleHasSiblings ? (
              <>
                <span className="tabular-nums">{ruleSiblings.length}</span> findings on <span className="tabular-nums">{ruleAssetCount}</span> {ruleAssetCount === 1 ? 'target' : 'targets'}, <span className="tabular-nums">{ruleActiveCount}</span> active{ruleComplete ? '' : ', among findings read so far'}
              </>
            ) : ruleComplete
              ? 'No other target has this finding.'
              : 'No other target read so far has this finding.'}
          </p>
          {checkId && !ruleComplete && ruleSource.state === 'ready' && ruleSource.envelope?.total !== null && ruleSource.envelope?.total !== undefined ? (
            <div className="rule-assets-more">
              <span className="muted small">{`Read ${ruleSource.items.length} of ${ruleSource.envelope.total} findings for this check.`}</span>
              {ruleSource.error ? <span className="small" role="alert">{ruleSource.error}</span> : null}
              <Button size="sm" variant="secondary" loading={ruleSource.loadingMore} onClick={ruleSource.loadMore}>Read more findings for this check</Button>
            </div>
          ) : null}
          {!checkId && !ruleComplete ? <p className="muted small">This finding has no check ID, so only the loaded page of findings is compared.</p> : null}
          {checkId && ruleSource.state === 'error' ? <p className="small" role="alert">{`Findings for this check could not load: ${ruleSource.error}`}</p> : null}
          {ruleHasSiblings ? (
            <DataTable
              className="rule-assets-table"
              columns={ruleAssetColumns}
              items={ruleSiblings}
              getRowId={(item, index) => getString(item, ['id'], String(index))}
              getRowProps={(item) => (getString(item, ['id'], '') === entityId ? { className: 'is-current-asset', 'aria-current': 'true' } : {})}
              empty={<span className="muted">No findings recorded for this finding group.</span>}
            />
          ) : null}
        </CardContent>
      </Card>
      </section>

      <Card data-od-id="finding-remediation" className="finding-remediation-card">
        <CardHeader>
          <div>
            <CardTitle>Remediation</CardTitle>
            <CardDescription>WAF action tracking and owner assignment when a playbook is linked to this finding.</CardDescription>
          </div>
        </CardHeader>
        <CardContent className="finding-remediation-body">
          {hasRemediationPlaybook ? (
            <>
              <div className="finding-remediation-meta">
                <div className="rem-cell"><span className="rem-label">Action</span><span className="rem-value mono">{remediation.remAction || 'Not reported'}</span></div>
                <div className="rem-cell"><span className="rem-label">Owner</span><span className="rem-value">{remediation.remOwner || 'Not reported'}</span></div>
                <div className="rem-cell"><span className="rem-label">State</span><Badge tone={remStateTone(remediation.remStateClass, remediation.remState)} title={`Recorded remediation state: ${plainCodeLabel(remediation.remState)}`}>{plainCodeLabel(remediation.remState, 'Not reported')}</Badge></div>
                <div className="rem-cell"><span className="rem-label">SLA</span><span className="rem-value">{remediation.remSla || 'Not reported'}</span></div>
              </div>
              {remediation.remDescription ? (
                <p className="finding-remediation-desc">{remediation.remDescription}</p>
              ) : null}
              {remSteps.length > 0 ? (
                <ol className="rem-steps">
                  {remSteps.map((step, index) => (
                    <li key={`${index}-${step}`}><span className="mono">{String(index + 1).padStart(2, '0')}</span> {step}</li>
                  ))}
                </ol>
              ) : null}
              {canWriteFinding ? (
              <form className="product-form product-form--compact" onSubmit={(event) => {
                event.preventDefault();
                const form = new FormData(event.currentTarget);
                const owner = String(form.get('rem_owner') ?? '').trim();
                void patchFinding({ rem_owner: owner, assignee: owner }, 'Remediation owner reassigned.', 'remediation-owner');
              }}>
                <label className="full">
                  <span>Remediation owner</span>
                  <input key={remediation.remOwner} name="rem_owner" defaultValue={remediation.remOwner} placeholder="team or user" />
                </label>
                <div className="row-actions action-bar-compact full">
                  <Button type="submit" size="sm" variant="secondary" loading={busy === `finding-remediation-owner-${entityId}`} disabled={busy !== ''}>Reassign owner</Button>
                  <Button type="button" size="sm" variant="ghost" disabled={!remediation.actionItemId} loading={busy === `deliver-${entityId}`} onClick={() => void markDelivered()}>Mark delivered</Button>
                </div>
              </form>
              ) : <RoleRestrictedCard title="Remediation changes are read-only for your role." />}
            </>
          ) : (
            <EmptyState
              icon={Wrench}
              title="No remediation playbook linked"
              body="This finding has no WAF action item or remediation steps yet. Use triage above to assign an owner, or link a playbook when your integration provides one."
            />
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <div>
            <CardTitle>Evidence bundle</CardTitle>
            <CardDescription>Recorded artifacts, source runs, sealed digests, and custody positions.</CardDescription>
          </div>
          <div className="row-actions">
            <Button size="sm" variant="ghost" loading={busy === `verify-${entityId}`} disabled={evidence === null || busy !== ''} onClick={() => void verifyChain()}>Verify chain</Button>
            <Button size="sm" variant="secondary" loading={busy === `export-${entityId}`} disabled={busy !== ''} onClick={() => void exportBundle()}>Export evidence</Button>
          </div>
        </CardHeader>
        <CardContent>
          {evidence === null ? <PortalLoadingSkeleton rows={3} /> : evidence.error ? (
            <EmptyState
              icon={FileCheck2}
              title="Evidence unavailable"
              body={evidence.error}
              actionLabel="Retry"
              onAction={() => setEvidenceReloadToken((value) => value + 1)}
            />
          ) : evidence.artifacts.length > 0 ? (
            <>
              <p className="muted small">Artifacts recorded for this finding's originating execution. Select one to inspect it; a recorded digest is not a verified custody chain until you run Verify chain.</p>
              <DataTable
                columns={artifactColumns}
                items={evidence.artifacts}
                getRowId={(item) => getString(item, ['id'], '')}
                getRowProps={(item) => {
                  const props = evidenceRowNavProps(getString(item, ['id'], ''), inspectArtifact);
                  return getString(item, ['id'], '') && inspected?.entry === 'artifact' && inspected.evidence_id === getString(item, ['id'], '')
                    ? { ...props, className: `${props.className ?? ''} is-selected`, 'aria-current': 'true' }
                    : props;
                }}
                empty={<span className="muted">No artifacts in bundle.</span>}
              />
            </>
          ) : (
            <EmptyState icon={FileCheck2} title="No evidence artifacts" body={plainEmptyReason(getString(evidence.meta, ['empty_reason'], 'Evidence bundle contains no artifacts for this finding.'))} />
          )}
        </CardContent>
      </Card>

      <Card className="finding-custody-card">
        <CardHeader>
          <div><CardTitle>Custody chain</CardTitle><CardDescription>Verification is shown only after the exported evidence and custody manifest pass the verification check.</CardDescription></div>
          <Badge tone={chainVerified === true ? 'success' : chainVerified === false ? 'danger' : 'muted'}>{custodyStatus}</Badge>
        </CardHeader>
        <CardContent>
          {evidence === null ? <PortalLoadingSkeleton rows={2} /> : evidence.error ? (
            <EmptyState icon={FileCheck2} title="Custody manifest unavailable" body={evidence.error} actionLabel="Retry" onAction={() => setEvidenceReloadToken((value) => value + 1)} />
          ) : (
            <details className="technical-disclosure">
              <summary>Show technical custody record</summary>
              <pre className="code" tabIndex={0} role="region" aria-label="Finding custody chain YAML">{custodyYaml}</pre>
            </details>
          )}
        </CardContent>
      </Card>
        </>
      ) : null}
    </div>
  );
}
