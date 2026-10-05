import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import {
  ArrowLeft,
  Check,
  ChevronDown,
  ChevronUp,
  Copy,
  ExternalLink,
  Eye,
  FileCheck2,
  History,
  Pencil,
  Play,
  Plus,
  RefreshCw,
  ShieldCheck,
  Square,
  Target,
  TriangleAlert,
  X,
} from 'lucide-react';
import { dedupeFindingsForTarget, type TargetDeduplicatedFinding } from '../lib/findings-helpers';
import {
  CRITICALITY_VALUES,
  SERVICE_ROLES,
  declarationDraftFrom,
  fetchTargetObservations,
  issueOwnershipChallenge,
  patchTargetDeclaration,
  patchTargetTags,
  populateTargetDetail,
  verifyOwnershipChallenge,
  type DeclarationDraft,
  type ObservationHistory,
  type OwnershipChallenge,
  type TargetDetailPayload,
} from '../lib/target-detail-api';
import { hasEvidenceBackedVerdict, publishedRunVerdict } from '../lib/run-verdict';
import { findingStatus, isFindingOpen } from '../lib/finding-lifecycle.mjs';
// @ts-ignore Plain ESM keeps truthfulness rules executable in focused node tests.
import { addTargetTag, apiErrorCode, edgeDetectionReasonExplanation, isTargetRunEligible, ownershipMethodLabel, ownershipStepStatus, removeTargetTag, targetDeclarationProvenanceLabel, targetDisplayValue, uniqueRecentRuns, uniqueVerificationHistory } from '../lib/target-detail.mjs';
import { VerifyChip, resolveTargetVerificationProvenance } from '../lib/verify-chip';
import { buildDetailHref, getRouteParam, replaceRouteParams } from '../lib/route-params';
import type { DataItem, PortalConfig, Session } from '../lib/types';
import { formatDate, formatSeverityLabel } from '../lib/utils';
import { AnchorButton, Button } from '../components/ui/button';
import { EmptyState } from '../components/ui/empty-state';
import { emptyStateFromApi } from '../lib/empty-from-api';
import { DataTable, type TableColumn } from '../components/ui/table';
import { Badge, type BadgeProps } from '../components/ui/badge';
import { Tabs } from '../components/ui/tabs';
import { Toast } from '../components/ui/toast';
import { canStartRun } from '../lib/run-permissions.mjs';
import { requestJson } from '../lib/api';
import { prefersReducedMotion } from '../lib/motion';
import { apiErrorMessage } from '../lib/error-messages';
import { ConfirmModal } from '../lib/crud-ui';
import { isScanActive, nextPollDelay, scanErrorMessage } from '../lib/validation-scan.mjs';
import {
  EDGE_DETECTION_CHECK_ID,
  buildCheckRows,
  countRowStatuses,
  declarationOnlyChecks,
  edgeDetectionPhase,
  markerEffectiveness,
  originExposureDetail,
  originExposureStatus,
  providerFamilyRows,
  retainedCoveragePairs,
  runAllChecks,
  targetTabFromParam,
  validationScansPathForTarget,
  type CheckRow,
  type ProviderFamilyRow,
  type TargetTab,
} from '../lib/domain-checks.mjs';
import { CheckQueue, ProviderObservations } from '../components/targets/domain-protection';
import { TargetChangesHistory } from '../components/targets/target-history';
import { OriginRelations } from '../components/targets/origin-relations';
import { ProbeActivity } from '../components/targets/probe-activity';
import { DECLARATION_LIMITS, validateDeclarationDraft } from '../lib/domain-checks.mjs';
import { CancelScanDialog } from '../components/runs/validation-scans-table';
import { useInspectorRef, useOpenInspector } from '../components/evidence/use-inspector';
import { useInteractionHold, useStableList } from '../components/evidence/use-stable-list';
import { navScopeKey } from '../lib/nav-state.mjs';
import { evidenceModePresentation, plainCheckName, plainFindingTitle, plainVerdictLabel, plainVerificationLabel } from '../lib/plain-language.mjs';
import { PortalUnavailablePage } from './public-pages';
import './target-detail-view.css';

type StatTone = NonNullable<BadgeProps['tone']>;
type EdgeLocalState = '' | 'pending' | 'blocked' | 'error';
type ReviewPlan = { mode: 'single'; checkId: string } | { mode: 'all' } | { mode: 'detect' } | null;

const TARGET_RUNS_LIMIT = 500;
const EDGE_POLL_MS = 4_000;
const EDGE_POLL_MAX_MS = 3 * 60 * 1000;
const EDGE_BLOCKED_RETRY_MS = 15_000;
const EDGE_BLOCKED_MAX_RETRIES = 20;
const DNS_RECHECK_MS = 30_000;
const DNS_RECHECK_MAX_MS = 15 * 60 * 1000;
const ACTIVE_STEP_STATUSES = new Set(['pending', 'deferred', 'starting', 'running', 'collecting']);
const SEVERITY_RANK: Record<string, number> = { critical: 5, s1: 5, high: 4, s2: 4, medium: 3, moderate: 3, s3: 3, low: 2, s4: 2, info: 1 };

const PAIR_REASON_LABELS: Record<string, string> = {
  missing_check_version: 'Check version not recorded',
  missing_scenario_version: 'Scenario version not recorded',
  check_version_mismatch: 'Recorded with a different check version',
  scenario_version_mismatch: 'Recorded with a different scenario version',
  stale: 'Outside the coverage freshness window',
  unfinalized: 'Run not finalized',
  canceled: 'Run canceled',
  observation_time_unknown: 'Completion time not recorded',
  simulation: 'Simulated, no live traffic',
  internal_simulation: 'Simulated, no live traffic',
  manual_declaration: 'Manual declaration',
  customer_declaration: 'Customer declaration',
  no_evidence: 'No evidence cited',
  not_finalized: 'Run not finalized',
};

const DIMENSION_LABELS: Record<string, string> = {
  application: 'Application',
  origin: 'Origin lockdown',
  network: 'Network and transport',
  dns: 'DNS',
  operations: 'Operations',
  other: 'Other',
};

const ROLE_LABELS: Record<string, string> = { website: 'Website', api: 'API', login: 'Login', dns: 'DNS service', network: 'Network endpoint' };

function getString(item: DataItem | null | undefined, keys: string[], fallback = 'Not reported') {
  if (!item) return fallback;
  for (const key of keys) {
    const value = item[key];
    if (value !== undefined && value !== null && value !== '') return String(value);
  }
  return fallback;
}

function asDataItem(value: unknown): DataItem | null {
  return value && typeof value === 'object' && !Array.isArray(value) ? (value as DataItem) : null;
}

function formatLabel(value: string, fallback = 'Not reported') {
  const trimmed = value.trim();
  if (!trimmed) return fallback;
  const friendly: Record<string, string> = {
    fqdn: 'Domain name',
    ip: 'IP address',
    cidr: 'CIDR range',
    hostname: 'Hostname',
    url: 'URL',
    cloud_baseline: 'Protected path baseline',
    must_block_before_origin: 'Block before the origin server',
  };
  const key = trimmed.toLowerCase();
  if (friendly[key]) return friendly[key];
  const label = trimmed.replace(/_/g, ' ');
  return label.charAt(0).toUpperCase() + label.slice(1);
}

function runOutcomeTone(value: string): StatTone {
  const key = value.trim().toLowerCase();
  if (['pass', 'passed', 'protected', 'complete', 'completed', 'succeeded'].includes(key)) return 'success';
  if (['gap', 'fail', 'failed', 'bypassable', 'penetrated', 'unprotected', 'error', 'cancelled'].includes(key)) return 'danger';
  if (['pending', 'planned', 'queued', 'running', 'collecting'].includes(key)) return 'info';
  return 'muted';
}

function severityTone(value: string): StatTone {
  const rank = SEVERITY_RANK[value.trim().toLowerCase()] ?? 0;
  if (rank >= 4) return 'danger';
  if (rank === 3) return 'warn';
  return 'muted';
}

/**
 * ADR-0008: agents are gone and verdicts are external-probe only. Legacy records may still carry
 * `agent_verified`; the server ranks that proof unverified, so the UI asks for re-verification.
 */
function ownershipLabel(state: string) {
  return /agent/i.test(state) ? 'Re-verify ownership' : plainVerificationLabel(state);
}

function ownershipMethodText(verification: DataItem | null) {
  const raw = ownershipMethodLabel(verification) as string;
  return /agent/i.test(raw) ? 'Recorded ownership evidence' : raw;
}

function recentRunVerdict(run: DataItem) {
  const normalizedRun = { ...run, id: getString(run, ['run_id', 'id'], ''), evidence_ids: run.evidence_ids };
  return hasEvidenceBackedVerdict(normalizedRun, []) ? publishedRunVerdict(normalizedRun) : '';
}

function CopyButton({ value, label }: { value: string; label: string }) {
  const [copied, setCopied] = useState(false);
  if (!value) return null;
  return (
    <Button
      size="sm"
      variant="ghost"
      aria-label={`Copy ${label}`}
      onClick={async () => {
        try {
          await navigator.clipboard?.writeText(value);
          setCopied(true);
          setTimeout(() => setCopied(false), 2000);
        } catch {
          setCopied(false);
        }
      }}
    >
      {copied ? <Check size={14} aria-hidden="true" /> : <Copy size={14} aria-hidden="true" />}
      {copied ? 'Copied' : 'Copy'}
    </Button>
  );
}

function TagEditor({ tags, canEdit, onChange }: { tags: string[]; canEdit: boolean; onChange: (next: string[]) => Promise<void> }) {
  const [draft, setDraft] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  async function commit(next: string[]) {
    setBusy(true);
    try {
      await onChange(next);
      setError('');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not save tags.');
    } finally {
      setBusy(false);
    }
  }

  async function addFromDraft() {
    const result = addTargetTag(tags, draft) as { tags: string[]; error: string };
    if (result.error) { setError(result.error); return; }
    setError('');
    setDraft('');
    if (result.tags.length !== tags.length) await commit(result.tags);
  }

  return (
    <div className="td-tag-block">
      <div className="td-tags">
        {tags.length === 0 ? <span className="td-tag-empty">No tags</span> : null}
        {tags.map((tag) => (
          <span key={tag} className="td-tag badge-identifier">
            {tag}
            {canEdit ? (
              <button type="button" aria-label={`Remove tag ${tag}`} disabled={busy} onClick={() => void commit(removeTargetTag(tags, tag) as string[])}>
                <X size={13} aria-hidden="true" />
              </button>
            ) : null}
          </span>
        ))}
      </div>
      {canEdit ? (
        <div className="td-tag-form">
          <input
            type="text"
            value={draft}
            placeholder="Add a tag, e.g. env:prod"
            aria-label="Add a tag to this target"
            aria-invalid={error ? true : undefined}
            aria-describedby={error ? 'td-tag-error' : undefined}
            autoComplete="off"
            disabled={busy}
            onChange={(event) => setDraft(event.target.value)}
            onKeyDown={(event) => {
              if (event.key === 'Enter') { event.preventDefault(); void addFromDraft(); }
            }}
          />
          <Button size="sm" variant="secondary" disabled={busy || !draft.trim()} loading={busy} onClick={() => void addFromDraft()}>
            <Plus size={14} aria-hidden="true" />Add tag
          </Button>
          {error ? <span className="td-tag-error" id="td-tag-error" role="alert">{error}</span> : null}
        </div>
      ) : null}
    </div>
  );
}

function declarationSummary(declaration: DataItem | null) {
  if (!declaration) return null;
  const roles = Array.isArray(declaration.service_roles) ? (declaration.service_roles as unknown[]).map(String) : [];
  const owner = asDataItem(declaration.owner);
  const criticality = asDataItem(declaration.criticality);
  const sourced = (row: DataItem | null, valueKey: string) => {
    const status = getString(row, ['status'], 'unassigned');
    if (status === 'unassigned') return { text: 'Unassigned', source: '' };
    const value = getString(row, [valueKey], '');
    return { text: value ? formatLabel(value) : 'Not recorded', source: status === 'inherited' ? 'inherited from group' : 'declared' };
  };
  const inherited = (key: string) => getString(declaration, [key], '') === 'inherited' ? 'inherited from group' : '';
  return {
    purpose: getString(declaration, ['purpose'], ''),
    purposeSource: inherited('purpose_status'),
    roles: roles.map((role) => ROLE_LABELS[role] ?? formatLabel(role)),
    rolesSource: inherited('service_roles_status'),
    owner: sourced(owner, 'label'),
    criticality: sourced(criticality, 'value'),
  };
}

/** Focused inline editor for the authoritative audited declaration fields only. */
function DeclarationEditor({
  declaration,
  onCancel,
  onSave,
}: {
  declaration: DataItem | null;
  onCancel: () => void;
  onSave: (initial: DeclarationDraft, draft: DeclarationDraft) => Promise<void>;
}) {
  const initial = useMemo(() => declarationDraftFrom(declaration), [declaration]);
  const [draft, setDraft] = useState<DeclarationDraft>(initial);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const headingRef = useRef<HTMLHeadingElement>(null);
  const dirty = JSON.stringify(draft) !== JSON.stringify(initial);
  const fieldErrors = validateDeclarationDraft(draft);
  const invalid = Boolean(fieldErrors.purpose || fieldErrors.owner_label);

  useEffect(() => { headingRef.current?.focus(); }, []);

  function cancel() {
    if (dirty && !window.confirm('Discard unsaved changes to the declared context?')) return;
    onCancel();
  }

  return (
    <form
      className="td-declaration-form"
      aria-labelledby="td-declaration-title"
      onSubmit={async (event) => {
        event.preventDefault();
        if (busy || invalid) return;
        setBusy(true);
        setError('');
        try {
          await onSave(initial, draft);
        } catch (err) {
          setError(apiErrorMessage(err, 'Declared context could not be saved.'));
        } finally {
          setBusy(false);
        }
      }}
      onKeyDown={(event) => {
        if (event.key === 'Escape') { event.preventDefault(); cancel(); }
      }}
    >
      <h3 id="td-declaration-title" ref={headingRef} tabIndex={-1}>Edit declared context</h3>
      <p className="td-muted">Recorded as your declaration and audited. Only fields you change are saved; untouched fields keep inheriting from the group. It never grants scope and never changes the target value or kind.</p>
      <label className="td-field">
        <span>Purpose</span>
        <input
          value={draft.purpose}
          aria-invalid={fieldErrors.purpose ? true : undefined}
          aria-describedby="td-purpose-help"
          onChange={(event) => setDraft({ ...draft, purpose: event.target.value })}
          placeholder="For example, checkout web"
        />
        <span id="td-purpose-help" className={fieldErrors.purpose ? 'td-form-error' : 'td-muted'}>{fieldErrors.purpose ?? `${draft.purpose.trim().length}/${DECLARATION_LIMITS.purpose} characters`}</span>
      </label>
      <fieldset className="td-field">
        <legend>Service roles</legend>
        <div className="td-role-options">
          {SERVICE_ROLES.map((role) => (
            <label key={role} className="td-role-option">
              <input
                type="checkbox"
                checked={draft.service_roles.includes(role)}
                onChange={(event) => setDraft({
                  ...draft,
                  service_roles: event.target.checked ? [...draft.service_roles, role] : draft.service_roles.filter((entry) => entry !== role),
                })}
              />
              {ROLE_LABELS[role]}
            </label>
          ))}
        </div>
        <span className="td-muted">None selected means unclassified.</span>
      </fieldset>
      <label className="td-field">
        <span>Owner</span>
        <input
          value={draft.owner_label}
          aria-invalid={fieldErrors.owner_label ? true : undefined}
          aria-describedby="td-owner-help"
          onChange={(event) => setDraft({ ...draft, owner_label: event.target.value })}
          placeholder="Team or contact label"
        />
        <span id="td-owner-help" className={fieldErrors.owner_label ? 'td-form-error' : 'td-muted'}>{fieldErrors.owner_label ?? `${draft.owner_label.trim().length}/${DECLARATION_LIMITS.owner_label} characters`}</span>
      </label>
      <label className="td-field">
        <span>Criticality</span>
        <select value={draft.criticality} onChange={(event) => setDraft({ ...draft, criticality: event.target.value as DeclarationDraft['criticality'] })}>
          <option value="">Unassigned</option>
          {CRITICALITY_VALUES.map((value) => <option key={value} value={value}>{formatLabel(value)}</option>)}
        </select>
      </label>
      {error ? <p className="td-form-error" role="alert">{error}</p> : null}
      <div className="td-form-actions">
        <Button type="submit" loading={busy} disabled={busy || !dirty || invalid}>Save context</Button>
        <Button type="button" variant="ghost" disabled={busy} onClick={cancel}>Cancel</Button>
      </div>
    </form>
  );
}

function buildOwnershipHistory(verification: DataItem | null) {
  const rawHistory = Array.isArray(verification?.history) ? verification.history : [];
  return uniqueVerificationHistory(rawHistory) as DataItem[];
}

function readTab(): TargetTab {
  return targetTabFromParam(getRouteParam('tab'));
}

export function TargetDetailView({
  entityId,
  config,
  session,
  checks,
  targetGroups = [],
  wafEdgeEnabled = false,
  onRefresh,
}: {
  entityId: string;
  config: PortalConfig;
  session: Session;
  checks: DataItem[];
  targetGroups?: DataItem[];
  /** Tenant deployment feature `waf_posture`; WAF/CDN detection routes 404 without it. */
  wafEdgeEnabled?: boolean;
  onRefresh: () => Promise<void>;
}) {
  const [detail, setDetail] = useState<TargetDetailPayload | null>(null);
  const [busy, setBusy] = useState('');
  const [error, setError] = useState('');
  const [banner, setBanner] = useState('');
  const [selectedCheckId, setSelectedCheckId] = useState(() => getRouteParam('check'));
  const [tab, setTabState] = useState<TargetTab>(readTab);
  const [scan, setScan] = useState<DataItem | null>(null);
  const [scanActivity, setScanActivity] = useState<DataItem[]>([]);
  const [selectedRunEvents, setSelectedRunEvents] = useState<DataItem[]>([]);
  const [targetRuns, setTargetRuns] = useState<DataItem[]>([]);
  const [runsError, setRunsError] = useState('');
  const [edgeLocal, setEdgeLocal] = useState<EdgeLocalState>('');
  const [edgeError, setEdgeError] = useState('');
  const [edgeReason, setEdgeReason] = useState('');
  const [review, setReview] = useState<ReviewPlan>(null);
  const [stopOpen, setStopOpen] = useState(false);
  const [stopSingleRun, setStopSingleRun] = useState<{ id: string; name: string } | null>(null);
  const [editingContext, setEditingContext] = useState(false);
  const [dnsWatchStartedAt, setDnsWatchStartedAt] = useState(0);
  const edgeRetriesRef = useRef(0);
  const loadGeneration = useRef(0);
  const openInspector = useOpenInspector();
  const inspected = useInspectorRef();

  const reload = useCallback(async () => {
    const generation = loadGeneration.current;
    const refreshed = await populateTargetDetail(config, session, entityId);
    if (generation === loadGeneration.current) setDetail(refreshed);
    return refreshed;
  }, [config, session, entityId]);

  useEffect(() => {
    loadGeneration.current += 1;
    const generation = loadGeneration.current;
    setDetail((current) => ({
      ...(current ?? {
        target: null, verification: null, waf_posture: null, edge_detection: null,
        checks_applied: [], runs_recent: [], findings: [], loa: null, counts: null,
        tags: [], ownership_challenge: null, loading: true,
      }),
      loading: true,
    }));
    populateTargetDetail(config, session, entityId).then((payload) => {
      if (generation === loadGeneration.current) setDetail(payload);
    });
  }, [config, session, entityId]);

  // Tab and selected check live in the address so refresh, Back and shared links keep them.
  useEffect(() => {
    const sync = () => {
      setTabState(readTab());
      const check = getRouteParam('check');
      setSelectedCheckId((current) => (check && check !== current ? check : current));
    };
    window.addEventListener('hashchange', sync);
    window.addEventListener('popstate', sync);
    return () => {
      window.removeEventListener('hashchange', sync);
      window.removeEventListener('popstate', sync);
    };
  }, []);

  function setTab(next: TargetTab) {
    setTabState(next);
    replaceRouteParams({ tab: next === 'overview' ? null : next });
  }

  function selectCheck(checkId: string) {
    setSelectedCheckId(checkId);
    replaceRouteParams({ check: checkId || null });
  }

  const target = detail?.target ?? null;
  const verification = detail?.verification ?? null;
  const challenge: OwnershipChallenge = detail?.ownership_challenge ?? null;
  const tags = detail?.tags ?? [];
  const kind = getString(target, ['kind'], 'unknown');
  const eligibility = getString(target, ['eligibility'], 'unknown');
  const verificationState = getString(verification, ['state'], getString(target, ['verification_state'], 'unverified'));
  const ownershipProven = (ownershipStepStatus(verificationState, challenge) as { done: boolean }).done;
  const targetEligible = isTargetRunEligible(eligibility, verificationState);
  const rawProvenance = resolveTargetVerificationProvenance(target, verification);
  const provenance = /agent/i.test(rawProvenance) ? `Recorded ownership evidence for ${verificationState}.` : rawProvenance;
  const targetGroupId = getString(target, ['target_group_id'], '');
  const targetGroupName = getString(
    targetGroups.find((group) => getString(group, ['id'], '') === targetGroupId) ?? null,
    ['name'],
    getString(target, ['target_group_name'], targetGroupId),
  );
  const canWrite = canStartRun(session.role);
  const canStartBoundedRun = canStartRun(session.role);

  const runsRecentLatest = useMemo(() => uniqueRecentRuns(detail?.runs_recent) as DataItem[], [detail?.runs_recent]);
  const historyHold = useInteractionHold();
  const idOfRun = useCallback((run: DataItem) => getString(run, ['run_id', 'id'], ''), []);
  // New executions land at the top while the user may be reading or inspecting an older one.
  const runsLive = useStableList(runsRecentLatest, {
    scope: `${navScopeKey(session) || 'anon'}|target|${entityId}`,
    idOf: idOfRun,
    hold: historyHold.holding || inspected?.entry === 'check_result',
  });
  const runsRecent = runsLive.items;
  const findings = Array.isArray(detail?.findings) ? detail!.findings : [];
  const [expandedFindingHistoryId, setExpandedFindingHistoryId] = useState<string | null>(null);
  const deduplicatedFindings = useMemo(() => dedupeFindingsForTarget(findings, target, checks), [findings, target, checks]);
  const deduplicatedOpenFindings = useMemo(() => deduplicatedFindings.filter((item) => item.status === 'open'), [deduplicatedFindings]);
  const expandedFindingHistory = useMemo(
    () => deduplicatedFindings.find((item) => item.representativeId === expandedFindingHistoryId) ?? null,
    [deduplicatedFindings, expandedFindingHistoryId]
  );
  const ownershipHistory = buildOwnershipHistory(verification);
  const declaration = detail?.declaration ?? null;
  const declared = declarationSummary(declaration);

  const runAll = useMemo(() => (target ? runAllChecks(checks, target) as DataItem[] : []), [checks, target]);
  const declarationOnlyCount = useMemo(() => (target ? declarationOnlyChecks(checks, target).length : 0), [checks, target]);
  const checkRows = useMemo(() => buildCheckRows({ checks: runAll, scan, runs: targetRuns }) as CheckRow[], [runAll, scan, targetRuns]);
  const rowCounts = useMemo(() => countRowStatuses(checkRows) as Record<string, number>, [checkRows]);
  const effectiveSelectedCheckId = checkRows.some((row) => row.checkId === selectedCheckId) ? selectedCheckId : '';
  const selectedCheckMissing = Boolean(selectedCheckId) && !effectiveSelectedCheckId && checkRows.length > 0;
  const selectedRow = checkRows.find((row) => row.checkId === effectiveSelectedCheckId) ?? null;
  const checkNameById = useMemo(
    () => new Map(checks.map((check) => [getString(check, ['check_id', 'id'], ''), plainCheckName(getString(check, ['name', 'title'], ''))])),
    [checks],
  );
  const displayCheckName = (checkId: string) => checkNameById.get(checkId) || checkId || 'Unnamed check';

  const edgeDetection = detail?.edge_detection ?? null;
  const edgeRequest = detail?.edge_detection_request ?? null;
  const profileInput = { protection_profile: detail?.protection_profile ?? null, edge_detection: edgeDetection };
  const providerRows = useMemo(() => providerFamilyRows(profileInput), [detail?.protection_profile, edgeDetection]); // eslint-disable-line react-hooks/exhaustive-deps
  const effectiveness = useMemo(() => markerEffectiveness(profileInput), [detail?.protection_profile, edgeDetection]); // eslint-disable-line react-hooks/exhaustive-deps
  const originStatus = originExposureStatus(profileInput);
  const scanActive = isScanActive(scan);
  const activeStandalone = targetRuns.find((run) => ['running', 'collecting', 'planned'].includes(getString(run, ['status'], ''))
    && runAll.some((check) => getString(check, ['check_id'], '') === getString(run, ['check_id'], ''))) ?? null;
  const activeCheckRow = checkRows.find((row) => row.status === 'running' && row.runId) ?? null;
  const currentScanStep = Array.isArray(scan?.steps) ? (scan.steps as DataItem[]).find((step) => ['running', 'collecting', 'starting'].includes(getString(step, ['status'], '')) && getString(step, ['test_run_id'], '')) ?? null : null;
  const latestTargetRun = targetRuns[0] ?? null;
  const activityRow = selectedRow ?? activeCheckRow ?? checkRows.find((row) => row.runId === getString(latestTargetRun, ['id'], '')) ?? null;
  const activityRunId = selectedRow ? selectedRow.runId : getString(currentScanStep, ['test_run_id'], '') || getString(activeStandalone, ['id'], '') || getString(latestTargetRun, ['id'], '') || activityRow?.runId || '';
  const activityRunning = selectedRow ? selectedRow.status === 'running' : Boolean(currentScanStep || activeStandalone);
  const activityCheckName = selectedRow?.name || (currentScanStep ? displayCheckName(getString(currentScanStep, ['check_id'], '')) : activeStandalone ? displayCheckName(getString(activeStandalone, ['check_id'], '')) : activityRow?.name || (latestTargetRun ? displayCheckName(getString(latestTargetRun, ['check_id'], '')) : ''));
  const scanId = getString(scan, ['id'], '');
  const fingerprintStep = Array.isArray(scan?.steps)
    ? (scan!.steps as DataItem[]).find((step) => getString(step, ['check_id'], '') === EDGE_DETECTION_CHECK_ID) ?? null
    : null;
  const fingerprintStepActive = scanActive && ACTIVE_STEP_STATUSES.has(getString(fingerprintStep, ['status'], ''));
  const edgePhase = edgeDetectionPhase({
    eligible: targetEligible,
    edge: edgeDetection,
    request: edgeRequest,
    localRequest: edgeLocal,
    scanFingerprintActive: fingerprintStepActive,
  });
  const edgeEvaluating = edgePhase === 'evaluating';
  const edgeRequestRunId = getString(edgeRequest, ['test_run_id'], '');
  const ownershipStep = ownershipStepStatus(verificationState, challenge) as { tone: StatTone; label: string; done: boolean };
  const ownershipDone = ownershipStep.done;
  const edgeCheck = checks.find((check) => getString(check, ['check_id', 'id'], '') === EDGE_DETECTION_CHECK_ID) ?? null;

  const loadTargetActivity = useCallback(async () => {
    if (!targetGroupId) return;
    const [scanList, runList] = await Promise.all([
      requestJson(config, session, validationScansPathForTarget(targetGroupId, entityId)).catch(() => null) as Promise<DataItem | null>,
      requestJson(config, session, `/v1/test-runs?target_id=${encodeURIComponent(entityId)}&limit=${TARGET_RUNS_LIMIT}`)
        .then((value) => { setRunsError(''); return value; })
        .catch((err) => { setRunsError(apiErrorMessage(err, 'Recorded check results could not load.')); return null; }) as Promise<DataItem | null>,
    ]);
    if (scanList && Array.isArray(scanList.items)) {
      const activeScan = (scanList.items[0] as DataItem | undefined) ?? null;
      setScan(activeScan);
      const activeScanId = getString(activeScan, ['id'], '');
      if (activeScanId) {
        void requestJson(config, session, `/v1/validation-scans/${encodeURIComponent(activeScanId)}/activity`)
          .then((act) => {
            if (act && Array.isArray((act as DataItem).items)) setScanActivity((act as DataItem).items as DataItem[]);
          })
          .catch(() => undefined);
      }
    }
    if (runList && Array.isArray(runList.items)) setTargetRuns(runList.items as DataItem[]);
  }, [config, session, entityId, targetGroupId]);

  useEffect(() => {
    setScan(null);
    setScanActivity([]);
    setSelectedRunEvents([]);
    setTargetRuns([]);
    setEdgeLocal('');
    setEdgeError('');
    setEdgeReason('');
    setDnsWatchStartedAt(0);
    setStopSingleRun(null);
    edgeRetriesRef.current = 0;
  }, [entityId]);

  useEffect(() => { void loadTargetActivity(); }, [loadTargetActivity]);

  useEffect(() => {
    if (scanActive || !activeStandalone) return undefined;
    let busyPoll = false;
    const timer = window.setInterval(() => {
      if (busyPoll) return;
      busyPoll = true;
      void loadTargetActivity().finally(() => { busyPoll = false; });
    }, 2500);
    return () => window.clearInterval(timer);
  }, [scanActive, activeStandalone?.id, loadTargetActivity]);

  // Follow a multi-check run the user started. Results land in place; the selection never moves.
  useEffect(() => {
    if (!scanId || !scanActive) return undefined;
    let stopped = false;
    let timer: number | undefined;
    let errors = 0;
    let fingerprintWasActive = fingerprintStepActive;
    const poll = async () => {
      try {
        const [next, activity] = await Promise.all([
          requestJson(config, session, `/v1/validation-scans/${encodeURIComponent(scanId)}?advance=false`) as Promise<DataItem>,
          requestJson(config, session, `/v1/validation-scans/${encodeURIComponent(scanId)}/activity`).catch(() => null) as Promise<DataItem | null>,
        ]);
        if (stopped) return;
        errors = 0;
        setScan(next);
        if (activity && Array.isArray((activity as DataItem).items)) {
          setScanActivity((activity as DataItem).items as DataItem[]);
        }
        const step = Array.isArray(next.steps)
          ? (next.steps as DataItem[]).find((row) => getString(row, ['check_id'], '') === EDGE_DETECTION_CHECK_ID)
          : null;
        const fingerprintNowActive = ACTIVE_STEP_STATUSES.has(getString(step ?? null, ['status'], ''));
        if (fingerprintWasActive && !fingerprintNowActive) void reload().catch(() => undefined);
        fingerprintWasActive = fingerprintNowActive;
        if (!isScanActive(next)) {
          void loadTargetActivity();
          void reload().catch(() => undefined);
          void onRefresh().catch(() => undefined);
          return;
        }
      } catch {
        if (stopped) return;
        errors += 1;
      }
      const delay = nextPollDelay({ status: 'running', errorCount: errors });
      if (delay !== null) timer = window.setTimeout(() => { void poll(); }, delay);
    };
    timer = window.setTimeout(() => { void poll(); }, nextPollDelay({ status: 'running' }) ?? 2500);
    return () => {
      stopped = true;
      if (timer !== undefined) window.clearTimeout(timer);
    };
    // fingerprintStepActive is read once as the starting point; the loop tracks it afterwards.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [config, session, scanId, scanActive, loadTargetActivity]);

  // Load live probe events for selected check run if available
  useEffect(() => {
    const runId = selectedRow?.runId;
    if (!runId) {
      setSelectedRunEvents([]);
      return undefined;
    }
    let stopped = false;
    const fetchRunEvents = () => {
      requestJson(config, session, `/v1/test-runs/${encodeURIComponent(runId)}/events`)
        .then((res) => {
          if (!stopped && res && Array.isArray((res as DataItem).items)) {
            setSelectedRunEvents((res as DataItem).items as DataItem[]);
          }
        })
        .catch(() => undefined);
    };
    fetchRunEvents();
    if (selectedRow?.status === 'running') {
      const timer = window.setInterval(fetchRunEvents, 2500);
      return () => {
        stopped = true;
        window.clearInterval(timer);
      };
    }
    return () => { stopped = true; };
  }, [config, session, selectedRow?.runId, selectedRow?.status]);

  const queueEdgeDetection = useCallback(async () => {
    if (!targetGroupId) return;
    setEdgeLocal('pending');
    setEdgeError('');
    setEdgeReason('');
    try {
      await requestJson(config, session, '/v1/waf/edge-detection', {
        method: 'POST',
        body: { target_group_id: targetGroupId, target_id: entityId },
      });
      edgeRetriesRef.current = 0;
      await reload().catch(() => undefined);
      void loadTargetActivity();
    } catch (err) {
      if (apiErrorCode(err) === 'concurrent_run_blocked') {
        setEdgeLocal('blocked');
        return;
      }
      setEdgeLocal('error');
      setEdgeError(apiErrorMessage(err, 'WAF/CDN detection could not be queued.'));
    }
  }, [config, session, entityId, targetGroupId, loadTargetActivity, reload]);

  // Only after the user explicitly started detection: wait for the group's single run slot.
  useEffect(() => {
    if (edgeLocal !== 'blocked' || edgeDetection || scanActive) return undefined;
    if (edgeRetriesRef.current >= EDGE_BLOCKED_MAX_RETRIES) return undefined;
    const timer = window.setTimeout(() => {
      edgeRetriesRef.current += 1;
      void queueEdgeDetection();
    }, EDGE_BLOCKED_RETRY_MS);
    return () => window.clearTimeout(timer);
  }, [edgeLocal, edgeDetection, scanActive, queueEdgeDetection]);

  // While user-started detection is in flight, re-read the target until the result is persisted.
  useEffect(() => {
    if (!edgeEvaluating || edgeDetection || fingerprintStepActive) return undefined;
    let stopped = false;
    const startedAt = Date.now();
    const timer = window.setInterval(() => {
      if (stopped) return;
      if (Date.now() - startedAt > EDGE_POLL_MAX_MS) {
        window.clearInterval(timer);
        setEdgeLocal('');
        return;
      }
      void reload()
        .then((next) => {
          const status = getString(next?.edge_detection_request ?? null, ['run_status'], '').toLowerCase();
          if (next?.edge_detection || (status && !['pending', 'planned', 'queued', 'running', 'collecting'].includes(status))) {
            setEdgeLocal('');
            void loadTargetActivity();
          }
        })
        .catch(() => undefined);
    }, EDGE_POLL_MS);
    return () => {
      stopped = true;
      window.clearInterval(timer);
    };
  }, [edgeEvaluating, edgeDetection, fingerprintStepActive, loadTargetActivity, reload]);

  useEffect(() => {
    if (edgePhase !== 'no_result' || !edgeRequestRunId || !wafEdgeEnabled) return undefined;
    let cancelled = false;
    requestJson(config, session, `/v1/waf/edge-detection/${encodeURIComponent(edgeRequestRunId)}`)
      .then((payload) => { if (!cancelled) setEdgeReason(getString(payload as DataItem, ['reason'], '')); })
      .catch(() => undefined);
    return () => { cancelled = true; };
  }, [config, session, edgePhase, edgeRequestRunId, wafEdgeEnabled]);

  // DNS re-checks run only after the user chose Check now or issued a record in this visit.
  useEffect(() => {
    if (!dnsWatchStartedAt || !canWrite || ownershipDone || !challenge?.id || getString(challenge as unknown as DataItem, ['state'], '') !== 'pending' || !targetGroupId) return undefined;
    const challengeId = challenge.id;
    let busyCheck = false;
    const timer = window.setInterval(() => {
      if (busyCheck) return;
      if (Date.now() - dnsWatchStartedAt > DNS_RECHECK_MAX_MS) { window.clearInterval(timer); setDnsWatchStartedAt(0); return; }
      busyCheck = true;
      verifyOwnershipChallenge(config, session, targetGroupId, challengeId)
        .then(async (result) => {
          if ((result as DataItem)?.verified === true) {
            window.clearInterval(timer);
            setDnsWatchStartedAt(0);
            setBanner('Ownership proven. You can now review and start bounded checks on this target.');
            await onRefresh().catch(() => undefined);
            await reload().catch(() => undefined);
          }
        })
        .catch(() => undefined)
        .finally(() => { busyCheck = false; });
    }, DNS_RECHECK_MS);
    return () => window.clearInterval(timer);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [dnsWatchStartedAt, config, session, canWrite, ownershipDone, challenge?.id, challenge?.state, targetGroupId]);


  const singleDisabledReason = !canStartBoundedRun
    ? 'Your role can inspect evidence but cannot start checks.'
    : !targetEligible
      ? 'No runnable checks are eligible for this target.'
      : !effectiveSelectedCheckId
        ? 'Select a check in the list first.'
        : scanActive
          ? 'A multi-check run is in progress on this target.'
          : '';

  async function startReviewed() {
    if (!review || !target) return;
    if (review.mode === 'detect') {
      setReview(null);
      await queueEdgeDetection();
      return;
    }
    if (review.mode === 'single') {
      if (singleDisabledReason) return;
      setBusy('run');
      setError('');
      setBanner('');
      try {
        await requestJson(config, session, '/v1/test-runs', {
          method: 'POST',
          body: { target_group_id: targetGroupId, target_id: entityId, check_id: effectiveSelectedCheckId },
        });
        setReview(null);
        setBanner(`${displayCheckName(effectiveSelectedCheckId)} started. Its result and evidence appear on this check when recorded.`);
        await loadTargetActivity();
        await reload();
        void onRefresh().catch(() => undefined);
      } catch (err) {
        setReview(null);
        setError(apiErrorMessage(err, 'The check could not start.'));
      } finally {
        setBusy('');
      }
      return;
    }
    setBusy('run-all');
    setError('');
    setBanner('');
    try {
      const created = await requestJson(config, session, '/v1/validation-scans', {
        method: 'POST',
        body: {
          target_group_id: targetGroupId,
          target_id: entityId,
          check_ids: runAll.map((check) => getString(check, ['check_id'], '')).filter(Boolean),
          name: `All compatible checks · ${targetDisplayValue(target)}`.slice(0, 120),
        },
      }) as DataItem;
      setReview(null);
      setScan(created);
      setBanner(`Queued ${runAll.length} bounded checks to run one at a time. Results appear on each check as they land.`);
    } catch (err) {
      setReview(null);
      setError(scanErrorMessage((err as { payload?: unknown }).payload, apiErrorMessage(err, 'The multi-check run could not start.')));
    } finally {
      setBusy('');
    }
  }

  const runAllRequestBound = runAll.reduce((total, check) => {
    const max = Number((check.probe_profile as DataItem | undefined)?.max_requests);
    return total + (Number.isFinite(max) ? max : 0);
  }, 0);
  const runAllCategoryCount = new Set(checkRows.map((row) => row.category.id)).size;

  async function stopSingleCheck() {
    if (!stopSingleRun) return;
    setBusy('stop-check'); setError('');
    try {
      await requestJson(config, session, `/v1/test-runs/${encodeURIComponent(stopSingleRun.id)}/cancel`, {
        method: 'POST', body: { reason: 'Stopped from target execution activity' },
      });
      setStopSingleRun(null); setBanner('Check stopped. Its recorded activity and results are kept.');
      await loadTargetActivity(); await reload();
    } catch (reason) { setError(apiErrorMessage(reason, 'The check could not stop. Refresh its current state.')); }
    finally { setBusy(''); }
  }

  function openStopCheck(row: CheckRow) { if (row.runId) setStopSingleRun({ id: row.runId, name: row.name }); }

  async function saveTags(next: string[]) {
    if (!target) return;
    await patchTargetTags(config, session, targetGroupId, entityId, next);
    setBanner('Tags saved.');
    await onRefresh();
    await reload();
  }

  async function saveDeclaration(initial: DeclarationDraft, draft: DeclarationDraft) {
    await patchTargetDeclaration(config, session, entityId, initial, draft);
    setEditingContext(false);
    setBanner('Declared context saved and recorded in the audit log.');
    await reload();
  }

  async function issueOwnership() {
    if (!target) return;
    setBusy('issue');
    setError('');
    setBanner('');
    try {
      await issueOwnershipChallenge(config, session, targetGroupId, entityId);
      setBanner('DNS TXT record issued. Add it at your DNS provider, then choose Check now.');
      await reload();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not issue an ownership challenge.');
    } finally {
      setBusy('');
    }
  }

  async function checkOwnership() {
    if (!challenge?.id) return;
    setBusy('verify');
    setError('');
    setBanner('');
    try {
      const result = await verifyOwnershipChallenge(config, session, targetGroupId, challenge.id) as DataItem;
      const verified = result?.verified === true || getString(asDataItem(result.challenge), ['state']) === 'resolved';
      if (verified) {
        setDnsWatchStartedAt(0);
        setBanner('Ownership proven. You can now review and start bounded checks on this target.');
      } else {
        setDnsWatchStartedAt(Date.now());
        setBanner('The DNS TXT record was not found yet. DNS can take a few minutes; this page re-checks every 30 seconds for 15 minutes while it stays open.');
      }
      await onRefresh();
      await reload();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not check the DNS record.');
    } finally {
      setBusy('');
    }
  }

  function inspectProvider(row: ProviderFamilyRow) {
    openInspector({ entry: 'provider', target_id: entityId, family: row.family }, `provider-${row.family}`);
  }

  function inspectCheck(row: CheckRow) {
    if (!row.runId) return;
    openInspector({ entry: 'check_result', target_id: entityId, check_id: row.checkId, test_run_id: row.runId }, `check-evidence-${row.checkId}`);
  }

  function inspectRun(run: DataItem) {
    const runId = getString(run, ['run_id', 'id'], '');
    const checkId = getString(run, ['check_id'], '');
    if (!runId || !checkId) return;
    openInspector({ entry: 'check_result', target_id: entityId, check_id: checkId, test_run_id: runId }, `run-${runId}`);
  }

  function inspectFinding(finding: DataItem) {
    const id = getString(finding, ['id'], '');
    if (!id) return;
    openInspector({ entry: 'finding', finding_id: id, target_id: entityId, check_id: getString(finding, ['check_id'], '') || undefined }, `finding-${id}`);
  }

  const inspectedRunId = inspected?.entry === 'check_result' ? inspected.test_run_id ?? '' : '';
  const inspectedFindingId = inspected?.entry === 'finding' ? inspected.finding_id ?? '' : '';

  function renderOwnershipPanel(compact = false) {
    if (ownershipDone) {
      return <p className="td-muted">Verified via {ownershipMethodText(verification)}.</p>;
    }
    return (
      <div className="td-ownership">
        {!compact ? (
          <p className="td-copy">External checks stay blocked until you prove you control this target. Publish the DNS TXT record below, then choose Check now. We only check the declared hostname.</p>
        ) : null}
        {challenge && challenge.record_name ? (
          <>
            <div className="td-dns">
              <div className="td-dns-row"><span className="td-dns-key">Type</span><span className="td-dns-val">TXT</span><span /></div>
              <div className="td-dns-row">
                <span className="td-dns-key">Name</span>
                <span className="td-dns-val">{challenge.record_name}</span>
                <CopyButton value={challenge.record_name} label="DNS record name" />
              </div>
              <div className="td-dns-row">
                <span className="td-dns-key">Value</span>
                <span className="td-dns-val">{challenge.record_value}</span>
                <CopyButton value={challenge.record_value} label="DNS record value" />
              </div>
            </div>
            <div className="td-actions">
              {canWrite ? (
                <Button size="sm" loading={busy === 'verify'} disabled={busy !== ''} onClick={() => void checkOwnership()}>
                  <ShieldCheck size={15} aria-hidden="true" />Check now
                </Button>
              ) : <Badge tone="muted">Read-only role</Badge>}
              {canWrite ? (
                <Button size="sm" variant="ghost" loading={busy === 'issue'} disabled={busy !== ''} onClick={() => void issueOwnership()}>Reissue record</Button>
              ) : null}
              {challenge.expires_at ? <span className="td-muted">Expires {formatDate(challenge.expires_at)}</span> : null}
              {challenge.last_checked_at ? <span className="td-muted">Last checked {formatDate(challenge.last_checked_at)}</span> : null}
              {dnsWatchStartedAt ? <span className="td-muted" role="status">Re-checking every 30 seconds</span> : null}
            </div>
          </>
        ) : (
          <div className="td-actions">
            {canWrite ? (
              <Button size="sm" loading={busy === 'issue'} disabled={busy !== ''} onClick={() => void issueOwnership()}>
                <ShieldCheck size={15} aria-hidden="true" />Issue DNS TXT record
              </Button>
            ) : <Badge tone="muted">Ask an engineer or admin to prove ownership</Badge>}
          </div>
        )}
      </div>
    );
  }

  function renderHeader() {
    const hasTarget = Boolean(target);
    const title = hasTarget ? targetDisplayValue(target) : entityId;
    return (
      <header className="page-head td-page-head">
        <div className="td-identity">
          <a href="#targets" className="td-back"><ArrowLeft size={14} aria-hidden="true" />Targets</a>
          <div className="td-title-cluster">
            <h1 className="page-title mono">{title || 'Target'}</h1>
            {hasTarget ? (
              <div className="td-title-badges">
                <Badge tone={targetEligible ? 'success' : 'warn'} title={`Reported eligibility ${eligibility}; ownership ${verificationState}`}>
                  {targetEligible ? 'Validation unlocked' : 'Validation locked'}
                </Badge>
                <span className="td-kind-tag">{formatLabel(kind)}</span>
              </div>
            ) : null}
          </div>
          {hasTarget ? (
            <div className="td-context">
              {declared ? (
                <dl className="td-context-list" aria-label="Declared context">
                  <div><dt>Purpose</dt><dd>{declared.purpose || 'Not declared'}{declared.purposeSource ? <small> · {declared.purposeSource}</small> : null}</dd></div>
                  <div><dt>Service roles</dt><dd>{declared.roles.length ? declared.roles.join(' + ') : 'Unclassified'}{declared.rolesSource ? <small> · {declared.rolesSource}</small> : null}</dd></div>
                  <div><dt>Owner</dt><dd>{declared.owner.text}{declared.owner.source ? <small> · {declared.owner.source}</small> : null}</dd></div>
                  <div><dt>Criticality</dt><dd>{declared.criticality.text}{declared.criticality.source ? <small> · {declared.criticality.source}</small> : null}</dd></div>
                </dl>
              ) : (
                <p className="td-muted td-context-missing">Declared purpose, owner and criticality are not reported by this server yet.</p>
              )}
              <div className="td-metaline">
                {targetGroupId ? <a className="td-group-link" href={buildDetailHref('target-group-detail', targetGroupId)}>Group: {targetGroupName}</a> : <span>No group</span>}
                <span className="dot" aria-hidden="true">·</span>
                <span>Expected: {formatLabel(getString(target, ['expected_behavior', 'expected'], 'Not reported'))}</span>
              </div>
              <TagEditor tags={tags} canEdit={canWrite} onChange={saveTags} />
            </div>
          ) : null}
        </div>
        {hasTarget ? (
          <div className="td-head-actions">
            {canStartBoundedRun ? (
              <Button onClick={() => { setTab('validate'); window.requestAnimationFrame(() => document.getElementById(scanActive || activeStandalone ? 'probe-activity-title' : 'td-all-checks')?.scrollIntoView({ behavior: prefersReducedMotion() ? 'auto' : 'smooth', block: 'start' })); }}>
                <Play size={15} aria-hidden="true" />{scanActive || activeStandalone ? 'View activity' : 'Plan validation'}
              </Button>
            ) : null}
            {canStartBoundedRun && (scanActive || activeStandalone) ? (
              <Button variant="danger" onClick={() => scanActive ? setStopOpen(true) : setStopSingleRun({ id: getString(activeStandalone, ['id'], ''), name: displayCheckName(getString(activeStandalone, ['check_id'], '')) })}>
                <Square size={14} aria-hidden="true" />{scanActive ? 'Stop validation' : 'Stop current check'}
              </Button>
            ) : null}
            {declared && canWrite && !editingContext ? (
              <Button variant="secondary" onClick={() => setEditingContext(true)}><Pencil size={14} aria-hidden="true" />Edit context</Button>
            ) : null}
          </div>
        ) : null}
      </header>
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
    if (detail.status === 404 || (!detail.error && !detail.status)) {
      return <PortalUnavailablePage kind="record-missing" requestedLabel="Target" parentHref="#targets" parentLabel="Back to targets" />;
    }
    if (detail.status === 403) {
      return <PortalUnavailablePage kind="access-denied" requestedLabel="This target" role={session.role ?? ''} parentHref="#targets" parentLabel="Back to targets" />;
    }
    if (detail.error) {
      // A failed read is not a missing target: say so, keep the address, and offer Retry.
      return (
        <div className="content target-detail-view">
          {renderHeader()}
          <div role="alert" data-target-load-error="true">
            <EmptyState
              icon={TriangleAlert}
              title="Target details could not load."
              body={`${detail.error} No other target is shown in its place.`}
              actionLabel="Retry"
              onAction={() => void reload()}
              actions={<AnchorButton href="#targets" variant="secondary">Back to targets</AnchorButton>}
            />
          </div>
        </div>
      );
    }
    const emptyMeta = detail.meta && typeof detail.meta === 'object' ? detail.meta as DataItem : null;
    return (
      <div className="content target-detail-view">
        {renderHeader()}
        {emptyStateFromApi({ icon: Target, meta: emptyMeta, actionHref: '#targets', actionLabel: 'Back to targets' })}
      </div>
    );
  }

  const openFindings = findings
    .filter((finding) => isFindingOpen(finding))
    .sort((left, right) => (SEVERITY_RANK[getString(right, ['severity'], '').toLowerCase()] ?? 0) - (SEVERITY_RANK[getString(left, ['severity'], '').toLowerCase()] ?? 0));
  const topFinding = openFindings[0] ?? null;
  const recordedResults = (rowCounts.passed ?? 0) + (rowCounts.failed ?? 0) + (rowCounts.inconclusive ?? 0) + (rowCounts.observed ?? 0);
  const coverage = detail.coverage ?? null;
  const coveragePairs = Array.isArray(coverage?.pairs) ? (coverage!.pairs as DataItem[]).filter((pair) => pair && typeof pair === 'object') : [];
  const retainedPairs = retainedCoveragePairs(coveragePairs);
  const liveNotes: Record<string, string> = Object.fromEntries(retainedPairs.map((pair) => [
    getString(pair, ['check_id'], ''),
    (PAIR_REASON_LABELS[getString(pair, ['pair_reason'], '')] ?? formatLabel(getString(pair, ['pair_reason'], 'not_recorded'))).toLowerCase(),
  ]));
  const dimensions = Array.isArray(detail.protection_profile?.dimensions)
    ? (detail.protection_profile!.dimensions as DataItem[]).filter((row) => row && typeof row === 'object')
    : [];

  function renderNextAction(): ReactNode {
    if (!ownershipDone) {
      return (
        <section className="td-next" data-kind="ownership" aria-labelledby="td-next-title">
          <div className="td-next-head">
            <span className="td-label">Next step</span>
            <h2 id="td-next-title">Prove ownership to unlock validation</h2>
            <Badge tone={ownershipStep.tone}>{ownershipStep.label}</Badge>
          </div>
          {renderOwnershipPanel()}
        </section>
      );
    }
    if (topFinding) {
      const id = getString(topFinding, ['id'], '');
      return (
        <section className="td-next" data-kind="finding" aria-labelledby="td-next-title">
          <div className="td-next-head">
            <span className="td-label">Highest-priority open finding</span>
            <h2 id="td-next-title">{plainFindingTitle(topFinding, [target], checks)}</h2>
            <Badge tone={severityTone(getString(topFinding, ['severity'], ''))}>{formatSeverityLabel(getString(topFinding, ['severity'], 'unknown'))}</Badge>
          </div>
          <p className="td-copy">
            Opened {formatDate(topFinding.created_at ?? topFinding.opened_at)}
            {openFindings.length > 1 ? `. ${openFindings.length - 1} more open on this target.` : '.'}
            {' '}A later passing check does not close it; review the original evidence first.
          </p>
          <div className="td-actions">
            <Button size="sm" variant="secondary" data-focus-key={`finding-${id}`} onClick={() => inspectFinding(topFinding)}><Eye size={14} aria-hidden="true" />View evidence</Button>
            <AnchorButton size="sm" variant="ghost" href={buildDetailHref('finding-detail', id)}>Open full finding</AnchorButton>
            {openFindings.length > 1 ? <Button size="sm" variant="ghost" onClick={() => setTab('findings')}>All {openFindings.length} open findings</Button> : null}
          </div>
        </section>
      );
    }
    if (recordedResults === 0) {
      return (
        <section className="td-next" data-kind="plan" aria-labelledby="td-next-title">
          <div className="td-next-head">
            <span className="td-label">Next step</span>
            <h2 id="td-next-title">No recorded check results yet</h2>
          </div>
          <p className="td-copy">Ownership is verified. Choose a compatible check, review its bounds, then start it. Nothing runs until you do.</p>
          <div className="td-actions">
            <Button size="sm" variant="secondary" onClick={() => setTab('validate')}>Choose checks</Button>
          </div>
        </section>
      );
    }
    return (
      <section className="td-next" data-kind="results" aria-labelledby="td-next-title">
        <div className="td-next-head">
          <span className="td-label">Latest recorded results</span>
          <h2 id="td-next-title">No open findings on this target</h2>
        </div>
        <p className="td-copy">
          Passed checks show behavior in their recorded scenario only. {rowCounts.not_run ?? 0} compatible check{(rowCounts.not_run ?? 0) === 1 ? '' : 's'} have no result yet.
        </p>
        <div className="td-actions">
          <Button size="sm" variant="secondary" onClick={() => setTab('validate')}>Review checks</Button>
        </div>
      </section>
    );
  }

  function renderCoverage() {
    if (coverage) {
      const applicable = Number(coverage.applicable_count);
      const percentage = coverage.percentage === null || coverage.percentage === undefined ? null : Number(coverage.percentage);
      const countText = (value: unknown) => (value === null || value === undefined || value === '' || !Number.isFinite(Number(value)) ? 'Not recorded' : String(value));
      const cell = (label: string, key: string) => (
        <div key={key}><dt>{label}</dt><dd className="tabular-nums">{countText(coverage[key])}</dd></div>
      );
      return (
        <section className="td-coverage" aria-labelledby="td-coverage-title">
          <header className="td-section-head">
            <div>
              <h2 id="td-coverage-title">Check coverage</h2>
              <p>Applicable target and check pairs from the server plan ({getString(coverage, ['plan_version'], 'version not recorded')}).</p>
            </div>
            <span className="td-coverage-figure-wrap">
              <strong className="td-coverage-figure tabular-nums">{applicable > 0 && percentage !== null ? (percentage === 0 && Number(coverage.conclusive_count) > 0 ? '<1%' : `${percentage}%`) : 'Not applicable'}</strong>
              <span className="td-muted">{applicable > 0 && percentage !== null ? 'of applicable pairs have a conclusive result' : 'No applicable target and check pairs'}</span>
            </span>
          </header>
          <dl className="td-count-grid">
            {cell('Applicable', 'applicable_count')}
            {cell('Evaluated', 'evaluated_count')}
            {cell('Conclusive', 'conclusive_count')}
            {cell('Inconclusive', 'inconclusive_count')}
            {cell('Not run', 'not_run_count')}
            {cell('Stale', 'stale_count')}
            {cell('Unknown', 'unknown_count')}
            {cell('Partial', 'partial_count')}
            {cell('Excluded', 'excluded_count')}
          </dl>
          {Number(coverage.observation_only_count) > 0 ? (
            <p className="td-copy">{String(coverage.observation_only_count)} transport or liveness checks are observations only. They remain available under Validate and are excluded from conclusive coverage and Run all checks.</p>
          ) : null}
          {Array.isArray(coverage.inconclusive_reasons) && coverage.inconclusive_reasons.length > 0 ? (
            <div className="td-retained" role="note">
              <strong>Why checks are inconclusive</strong>
              <ul>
                {coverage.inconclusive_reasons.map((value) => {
                  const reason = asDataItem(value);
                  if (!reason) return null;
                  return <li key={getString(reason, ['reason'], '')}><strong>{String(reason.count)} · {getString(reason, ['label'], 'Evidence incomplete')}</strong><p className="td-copy">{getString(reason, ['next_step'], '')}</p></li>;
                })}
              </ul>
              <Button size="sm" variant="secondary" onClick={() => setTab('validate')}>Review check evidence</Button>
            </div>
          ) : null}
          {retainedPairs.length ? (
            <div className="td-retained" role="note">
              <strong>Recorded, not counted as current live coverage</strong>
              <p className="td-muted">These records are simulated, manual, stale, unfinished, or lack the version, completion time, or cited evidence needed for current coverage. Current external inconclusive results count as evaluated checks.</p>
              <ul>
                {retainedPairs.map((pair) => {
                  const retained = asDataItem(pair.retained);
                  return (
                    <li key={getString(pair, ['check_id'], '')}>
                      <span>{displayCheckName(getString(pair, ['check_id'], ''))}</span>
                      <span className="td-muted"> · {PAIR_REASON_LABELS[getString(pair, ['pair_reason'], '')] ?? formatLabel(getString(pair, ['pair_reason'], 'not_recorded'))}</span>
                      {retained ? <span className="td-muted"> · retained {formatLabel(getString(retained, ['verdict'], 'result'))}, {getString(retained, ['provenance'], '') ? `${formatLabel(getString(retained, ['provenance'], ''))} source` : 'source not recorded'}{retained.observed_at ? `, ${formatDate(retained.observed_at)}` : ''}</span> : null}
                    </li>
                  );
                })}
              </ul>
            </div>
          ) : null}
          {dimensions.length ? (
            <div className="td-dimensions" role="region" aria-label="Coverage by readiness dimension" tabIndex={0}>
              <table className="data-table">
                <caption className="sr-only">Applicable check coverage per readiness dimension. Coverage shows what was evaluated, not whether it passed.</caption>
                <thead><tr><th scope="col">Dimension</th><th scope="col">Coverage state</th><th scope="col">Evaluated</th><th scope="col">Conclusive</th><th scope="col">Not run</th><th scope="col">Unknown or partial</th><th scope="col">Stale</th><th scope="col">Excluded</th></tr></thead>
                <tbody>
                  {dimensions.map((dimension) => {
                    const applicableCount = Number(dimension.applicable_count);
                    return (
                      <tr key={getString(dimension, ['id'], '')}>
                        <th scope="row">{DIMENSION_LABELS[getString(dimension, ['id'], '')] ?? formatLabel(getString(dimension, ['id'], ''))}</th>
                        <td>{applicableCount > 0 ? formatLabel(getString(dimension, ['status'], 'not_recorded')) : 'Not applicable'}</td>
                        <td className="tabular-nums">{applicableCount > 0 ? `${dimension.evaluated_count ?? 0} of ${applicableCount}` : '0 of 0'}</td>
                        <td className="tabular-nums">{String(dimension.conclusive_count ?? 'Not recorded')}</td>
                        <td className="tabular-nums">{String(dimension.not_run_count ?? 'Not recorded')}</td>
                        <td className="tabular-nums">{dimension.unknown_count === undefined && dimension.partial_count === undefined ? 'Not recorded' : `${dimension.unknown_count ?? 0} / ${dimension.partial_count ?? 0}`}</td>
                        <td className="tabular-nums">{String(dimension.stale_count ?? 'Not recorded')}</td>
                        <td className="tabular-nums">{String(dimension.excluded_count ?? 'Not recorded')}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          ) : null}
          <p className="td-muted">Coverage shows which applicable checks have results, not whether they passed. Launch gates are re-evaluated by the server when you start a check.</p>
        </section>
      );
    }
    return (
      <section className="td-coverage" aria-labelledby="td-coverage-title">
        <header className="td-section-head">
          <div>
            <h2 id="td-coverage-title">Recorded check results</h2>
            <p>Counts over {checkRows.length} catalog checks compatible with this target kind. The server applicability plan is not reported yet, so no coverage percentage is shown.</p>
          </div>
        </header>
        <dl className="td-count-grid">
          <div><dt>Gap found</dt><dd className="tabular-nums">{rowCounts.failed ?? 0}</dd></div>
          <div><dt>Passed</dt><dd className="tabular-nums">{rowCounts.passed ?? 0}</dd></div>
          <div><dt>Inconclusive</dt><dd className="tabular-nums">{rowCounts.inconclusive ?? 0}</dd></div>
          <div><dt>Observed only</dt><dd className="tabular-nums">{rowCounts.observed ?? 0}</dd></div>
          <div><dt>Not run</dt><dd className="tabular-nums">{rowCounts.not_run ?? 0}</dd></div>
        </dl>
        {runsError ? <p className="td-form-error" role="alert">{runsError} Counts above may be incomplete.</p> : null}
      </section>
    );
  }

  function edgeNote(): ReactNode {
    if (!wafEdgeEnabled && !edgeDetection) return 'WAF/CDN detection is not enabled for this workspace.';
    if (edgePhase === 'locked') return 'WAF/CDN detection is not unlocked for this target.';
    if (edgePhase === 'waiting') return 'Another run holds this group’s single run slot. Your detection request starts when it frees up.';
    if (edgePhase === 'error') return edgeError || 'WAF/CDN detection could not be queued.';
    if (edgePhase === 'no_result') return edgeDetectionReasonExplanation(edgeReason) || 'The last detection run finished without a trusted result, so nothing is asserted.';
    if (edgePhase === 'not_started') return 'Detection has not run on this target. It starts only when someone chooses Detect WAF and CDN.';
    return null;
  }

  const detectAction = canStartBoundedRun && wafEdgeEnabled && targetEligible && !scanActive && !edgeEvaluating ? (
    <Button size="sm" variant="secondary" data-focus-key="td-detect" onClick={() => setReview({ mode: 'detect' })}>
      <RefreshCw size={14} aria-hidden="true" />{edgeDetection ? 'Detect again' : 'Detect WAF and CDN'}
    </Button>
  ) : null;

  const runColumns: TableColumn<DataItem>[] = [
    { key: 'check', label: 'Check', render: (item) => {
      const checkId = getString(item, ['check_id'], '');
      return <span className="entity-cell-stack"><strong>{displayCheckName(checkId)}</strong><small className="mono">{checkId}</small></span>;
    } },
    { key: 'status', label: 'Lifecycle', render: (item) => {
      const value = getString(item, ['status', 'run_status'], 'unknown');
      return <Badge tone={runOutcomeTone(value)} title="Recorded run lifecycle">{formatLabel(value)}</Badge>;
    } },
    { key: 'verdict', label: 'Result', render: (item) => {
      const value = recentRunVerdict(item);
      const evidenceCount = Array.isArray(item.evidence_ids) ? item.evidence_ids.length : 0;
      return value
        ? <Badge tone={runOutcomeTone(value)} title={`Technical verdict ${value}; cites ${evidenceCount} evidence record${evidenceCount === 1 ? '' : 's'}`}>{plainVerdictLabel(value)}</Badge>
        : <span className="td-muted">No evidence-backed result</span>;
    } },
    { key: 'mode', label: 'How it was checked', render: (item) => {
      const mode = evidenceModePresentation(item, checks.find((check) => getString(check, ['check_id', 'id'], '') === getString(item, ['check_id'], '')) ?? null);
      return <Badge tone={mode.tone} title={mode.detail}>{mode.label}</Badge>;
    } },
    { key: 'started', label: 'Started', render: (item) => formatDate(item.started_at ?? item.created_at) },
    { key: 'evidence', label: 'Evidence', render: (item) => {
      const runId = getString(item, ['run_id', 'id'], '');
      return (
        <Button size="sm" variant="ghost" data-focus-key={`run-${runId}`} disabled={!runId} onClick={(event) => { event.stopPropagation(); inspectRun(item); }} aria-label={`View evidence for ${displayCheckName(getString(item, ['check_id'], ''))} run ${runId}`}>
          <Eye size={14} aria-hidden="true" />View
        </Button>
      );
    } },
  ];

  const findingColumns: TableColumn<TargetDeduplicatedFinding>[] = [
    {
      key: 'severity',
      label: 'Severity',
      render: (item) => (
        <Badge tone={severityTone(item.severity)}>
          {formatSeverityLabel(item.severity || 'unknown')}
        </Badge>
      ),
    },
    {
      key: 'title',
      label: 'Finding',
      render: (item) => {
        const isMulti = item.detectionCount > 1;
        return (
          <span className="entity-cell-stack td-finding-cell-stack">
            <span className="td-finding-title-row">
              <a
                href={buildDetailHref('finding-detail', item.representativeId)}
                className="td-finding-link"
              >
                {item.title}
              </a>
              {isMulti ? (
                <span
                  className="td-occurrence-badge"
                  title={`Detected ${item.detectionCount} times across outside-in validation runs`}
                >
                  <History size={11} aria-hidden="true" />
                  {item.detectionCount} detections
                </span>
              ) : null}
            </span>
            <span className="td-finding-meta-row">
              <small className="mono">{item.representativeId}</small>
              {isMulti && item.firstOpenedAt && item.lastOpenedAt ? (
                <small className="td-history-time-span">
                  Detected {item.detectionCount}× · Latest: {formatDate(item.lastOpenedAt)}
                </small>
              ) : null}
            </span>
          </span>
        );
      },
    },
    {
      key: 'state',
      label: 'Lifecycle',
      render: (item) => formatLabel(item.state || 'open'),
    },
    {
      key: 'opened',
      label: 'Opened',
      render: (item) => (
        <span className="td-opened-stack">
          <span>{formatDate(item.lastOpenedAt ?? item.firstOpenedAt)}</span>
          {item.detectionCount > 1 ? (
            <small className="td-muted td-opened-hint">Latest of {item.detectionCount} detections</small>
          ) : null}
        </span>
      ),
    },
    {
      key: 'assignee',
      label: 'Assignee',
      render: (item) => item.assignee || <span className="td-muted">Unassigned</span>,
    },
    {
      key: 'evidence',
      label: 'Evidence & History',
      render: (item) => {
        const id = item.representativeId;
        const isMulti = item.detectionCount > 1;
        const isExpanded = expandedFindingHistoryId === id;
        return (
          <div className="td-finding-row-actions">
            <Button
              size="sm"
              variant="ghost"
              data-focus-key={`finding-${id}`}
              onClick={(event) => {
                event.stopPropagation();
                inspectFinding(item.representative);
              }}
              aria-label={`View evidence for finding ${id}`}
            >
              <Eye size={14} aria-hidden="true" />View
            </Button>
            {isMulti ? (
              <Button
                size="sm"
                variant={isExpanded ? 'secondary' : 'ghost'}
                className="td-history-btn"
                onClick={(event) => {
                  event.stopPropagation();
                  setExpandedFindingHistoryId(isExpanded ? null : id);
                }}
                aria-label={`Toggle detection history for finding ${id}`}
                aria-expanded={isExpanded}
              >
                <History size={13} aria-hidden="true" />
                History ({item.detectionCount})
                {isExpanded ? <ChevronUp size={13} aria-hidden="true" /> : <ChevronDown size={13} aria-hidden="true" />}
              </Button>
            ) : null}
          </div>
        );
      },
    },
  ];

  const workspaceTabs = [
    { id: 'overview' as const, label: 'Overview' },
    { id: 'validate' as const, label: 'Validate', count: checkRows.length },
    { id: 'findings' as const, label: 'Findings', count: openFindings.length },
    { id: 'history' as const, label: 'Changes & history' },
  ];

  const selectedBound = selectedRow?.maxRequests ?? null;

  return (
    <div className="content target-detail-view">
      {renderHeader()}
      {error ? (
        <Toast
          message={error}
          tone="error"
          duration={5000}
          onDismiss={() => setError('')}
        />
      ) : null}
      {banner && !error ? (
        <Toast
          message={banner}
          tone={banner.includes('not found') ? 'warn' : 'success'}
          duration={5000}
          onDismiss={() => setBanner('')}
        />
      ) : null}
      {editingContext && declared ? (
        <DeclarationEditor declaration={declaration} onCancel={() => setEditingContext(false)} onSave={saveDeclaration} />
      ) : null}

      <Tabs
        ariaLabel={`${targetDisplayValue(target)} workspace`}
        value={tab}
        options={workspaceTabs}
        onChange={setTab}
        getPanelId={(id) => `td-panel-${id}`}
        getTabId={(id) => `td-tab-${id}`}
      />

      <div className="td-panel" role="tabpanel" id={`td-panel-${tab}`} aria-labelledby={`td-tab-${tab}`}>
        {tab === 'overview' ? (
          <div className="td-overview">
            {renderNextAction()}
            <ProviderObservations
              rows={providerRows}
              effectiveness={effectiveness}
              originStatus={originStatus}
              originDetail={originExposureDetail(profileInput)}
              evaluating={edgeEvaluating}
              note={edgeNote()}
              action={detectAction}
              onInspect={inspectProvider}
            />
            {renderCoverage()}
            {target ? (
              <OriginRelations
                config={config}
                session={session}
                target={target}
                profile={(detail?.protection_profile as DataItem | undefined) ?? null}
                canWrite={canWrite}
                canStart={canStartBoundedRun}
                ownershipDone={ownershipDone}
                onStarted={(text) => { setBanner(text); void reload(); }}
                onChanged={() => { void reload(); }}
              />
            ) : null}
          </div>
        ) : null}

        {tab === 'validate' ? (
          <div className="td-validate">
            <section className="td-validate-head" aria-labelledby="td-validate-title">
              <div>
                <h2 id="td-validate-title">Validate this target</h2>
                <p className="td-copy">Select a check, review its bounds, then start it. Results and evidence stay on this check; the selection does not move when new results arrive.</p>
              </div>
              <div className="td-validate-gates">
                <Badge tone={ownershipStep.tone}>{ownershipDone ? 'Ownership verified' : ownershipStep.label}</Badge>
                {!canStartBoundedRun ? <Badge tone="muted">Read-only role</Badge> : null}
              </div>
            </section>
            {!ownershipDone ? renderOwnershipPanel(true) : null}
            {selectedCheckMissing ? (
              <div className="form-banner" role="status">
                The linked check <span className="mono">{selectedCheckId}</span> is not compatible with this target kind, so it is not listed. No other check was selected.
              </div>
            ) : null}
            <ProbeActivity
              config={config} session={session} runId={activityRunId}
              checkName={activityCheckName}
              running={activityRunning} canStop={canStartBoundedRun && Boolean(activityRunId)}
              onStop={() => setStopSingleRun({ id: activityRunId, name: activityCheckName || 'Current check' })}
              onFollowActive={selectedRow && activeCheckRow && selectedRow.checkId !== activeCheckRow.checkId ? () => selectCheck(activeCheckRow.checkId) : undefined}
              notSent={activityRow && !activityRunId && ['blocked', 'skipped', 'cancelled'].includes(activityRow.status) ? { reason: activityRow.reason, at: activityRow.finishedAt || activityRow.startedAt } : null}
            />
            <CheckQueue
              rows={checkRows}
              selectedCheckId={effectiveSelectedCheckId}
              canSelect
              onSelect={selectCheck}
              onInspect={inspectCheck}
              scan={scan}
              scanActive={scanActive}
              canRun={canStartBoundedRun}
              busy={busy === 'run-all'}
              onRunAll={() => setReview({ mode: 'all' })}
              onStop={() => setStopOpen(true)}
              onStopCheck={canStartBoundedRun ? openStopCheck : undefined}
              onActivity={(row) => { selectCheck(row.checkId); document.getElementById('probe-activity-title')?.scrollIntoView({ behavior: prefersReducedMotion() ? 'auto' : 'smooth', block: 'start' }); }}
              liveNotes={liveNotes}
              footer={declarationOnlyCount > 0 ? <p className="td-muted">{declarationOnlyCount} declaration-only checks are not listed because they send no traffic.</p> : null}
              scanActivity={scanActivity}
              selectedRunEvents={selectedRunEvents}
              targetValue={targetDisplayValue(target)}
            />
            {canStartBoundedRun && !scanActive && !activeStandalone ? (
              <div className="td-start-bar" role="region" aria-label="Start the selected check">
                <span className="td-start-copy">
                  {selectedRow ? <><strong>{selectedRow.name}</strong> on <span className="mono">{targetDisplayValue(target)}</span></> : 'No check selected'}
                </span>
                <Button
                  disabled={!targetEligible || !effectiveSelectedCheckId || busy !== '' || scanActive}
                  title={singleDisabledReason || undefined}
                  onClick={() => setReview({ mode: 'single', checkId: effectiveSelectedCheckId })}
                >
                  <Play size={15} aria-hidden="true" />Review and start
                </Button>
                {singleDisabledReason ? <span className="td-muted td-start-reason">{singleDisabledReason}</span> : null}
              </div>
            ) : null}
          </div>
        ) : null}

        {tab === 'findings' ? (
          <section aria-labelledby="td-findings-title" className="td-findings">
            <header className="td-section-head">
              <div>
                <h2 id="td-findings-title">Findings on this target</h2>
                <p>
                  {openFindings.length} open of {findings.length} recorded.
                  {deduplicatedFindings.length < findings.length
                    ? ` Deduplicated into ${deduplicatedFindings.length} unique finding${deduplicatedFindings.length === 1 ? '' : 's'}.`
                    : ''}{' '}
                  Each opens the full detection history and evidence.
                </p>
              </div>
            </header>
            <DataTable
              columns={findingColumns}
              items={deduplicatedFindings}
              getRowId={(item) => item.representativeId}
              getRowProps={(item) => (item.representativeId === inspectedFindingId ? { className: 'is-selected', 'aria-current': 'true' } : {})}
              empty={emptyStateFromApi({ icon: TriangleAlert, meta: detail.sectionMeta?.findings })}
            />

            {expandedFindingHistory ? (
              <div
                className="td-finding-history-drawer"
                role="region"
                aria-label={`Detection history for ${expandedFindingHistory.title}`}
              >
                <div className="td-finding-history-drawer-head">
                  <div className="td-finding-history-drawer-title">
                    <History size={16} aria-hidden="true" />
                    <div>
                      <h3>Detection history: {expandedFindingHistory.title}</h3>
                      <p className="td-muted">
                        {expandedFindingHistory.detectionCount} detections recorded across outside-in validation runs.
                      </p>
                    </div>
                  </div>
                  <div className="td-finding-history-drawer-actions">
                    <a
                      href={buildDetailHref('finding-detail', expandedFindingHistory.representativeId)}
                      className="btn btn-secondary btn-sm"
                    >
                      <ExternalLink size={13} aria-hidden="true" /> Detailed finding page
                    </a>
                    <Button
                      size="sm"
                      variant="ghost"
                      onClick={() => setExpandedFindingHistoryId(null)}
                      aria-label="Close detection history"
                    >
                      <X size={15} aria-hidden="true" />
                    </Button>
                  </div>
                </div>

                <div className="td-finding-history-drawer-list" role="list">
                  {expandedFindingHistory.detections.map((detection, index) => {
                    const detId = getString(detection, ['id'], '');
                    const runId = getString(detection, ['test_run_id', 'testRunId'], '');
                    const isLatest = index === 0;
                    const isInitial = index === expandedFindingHistory.detections.length - 1 && expandedFindingHistory.detectionCount > 1;
                    const openedDate = detection.opened_at ?? detection.created_at;
                    const detSeverity = getString(detection, ['severity'], 'medium');

                    return (
                      <div key={detId || index} className="td-drawer-history-item" role="listitem">
                        <div className="td-drawer-history-item-top">
                          <span className="td-drawer-history-time">{formatDate(openedDate)}</span>
                          {isLatest ? (
                            <Badge tone="warn">Latest detection</Badge>
                          ) : isInitial ? (
                            <Badge tone="default">Initial detection</Badge>
                          ) : (
                            <Badge tone="default">Detection #{expandedFindingHistory.detectionCount - index}</Badge>
                          )}
                          <Badge tone={severityTone(detSeverity)}>{formatSeverityLabel(detSeverity)}</Badge>
                          <span className="mono td-drawer-det-id">{detId}</span>
                        </div>
                        <div className="td-drawer-history-item-bottom">
                          {runId ? (
                            <span className="td-drawer-run-id">
                              Run: <span className="mono">{runId}</span>
                            </span>
                          ) : null}
                          <div className="td-drawer-actions">
                            <Button
                              size="sm"
                              variant="ghost"
                              onClick={() => inspectFinding(detection)}
                              aria-label={`View evidence for detection ${detId}`}
                            >
                              <Eye size={13} aria-hidden="true" /> View evidence
                            </Button>
                            <a
                              href={buildDetailHref('finding-detail', detId)}
                              className="td-inline-link"
                            >
                              Finding page
                            </a>
                          </div>
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>
            ) : null}
          </section>
        ) : null}

        {tab === 'history' ? (
          <div className="td-history-tab">
            <TargetChangesHistory
              config={config}
              session={session}
              targetId={entityId}
              profile={(detail?.protection_profile as DataItem | undefined) ?? null}
              checkName={(checkId) => plainCheckName(getString(checks.find((check) => getString(check, ['check_id', 'id'], '') === checkId) ?? {}, ['name', 'title'], checkId))}
              onInspectRun={(runId, checkId, focusKey) => openInspector({ entry: 'check_result', target_id: entityId, check_id: checkId, test_run_id: runId }, focusKey)}
            />
            <section aria-labelledby="td-runs-title">
              <header className="td-section-head">
                <div>
                  <h2 id="td-runs-title">Recorded check executions</h2>
                  <p>Newest first. View opens that execution’s own result and evidence; it never starts anything.</p>
                </div>
              </header>
              {runsLive.pending ? (
                <div className="live-update-pill" role="status">
                  <span>{runsLive.added ? `${runsLive.added} newer execution${runsLive.added === 1 ? '' : 's'} recorded.` : 'Execution records changed.'} The list is held as of {formatDate(runsLive.committedAt)}.</span>
                  <Button size="sm" variant="secondary" onClick={runsLive.apply}>Show updates</Button>
                </div>
              ) : null}
              <div {...historyHold.handlers}>
              <DataTable
                columns={runColumns}
                items={runsRecent}
                getRowId={(item) => getString(item, ['run_id', 'id'], '')}
                getRowProps={(item) => (getString(item, ['run_id', 'id'], '') === inspectedRunId ? { className: 'is-selected', 'aria-current': 'true' } : {})}
                empty={emptyStateFromApi({ icon: FileCheck2, meta: detail.sectionMeta?.runs })}
              />
              </div>
            </section>
            <section aria-labelledby="td-ownership-history-title">
              <header className="td-section-head">
                <div><h2 id="td-ownership-history-title">Ownership transitions</h2></div>
              </header>
              {ownershipHistory.length ? (
                <ul className="td-observation-history">
                  {ownershipHistory.map((item, index) => (
                    <li key={`${getString(item, ['state'], 'unknown')}-${index}`}>
                      <VerifyChip state={getString(item, ['state'], 'unknown')} provenance={`Recorded transition ${getString(item, ['state'], 'unknown')}`} label={ownershipLabel(getString(item, ['state'], 'unknown'))} />
                      <span className="td-muted">{item.transitioned_at ? formatDate(item.transitioned_at) : 'Time not recorded'}</span>
                    </li>
                  ))}
                </ul>
              ) : <p className="td-muted">No ownership transitions recorded.</p>}
            </section>
          </div>
        ) : null}
      </div>

      <section className="td-facts" aria-labelledby="td-facts-title">
        <header className="td-section-head"><div><h2 id="td-facts-title">Target facts</h2></div></header>
        <div className="table-wrap" tabIndex={0} role="region" aria-label="Target facts, scrollable">
          <table className="data-table">
            <tbody>
              <tr><td>Target ID</td><td><span className="mono">{entityId}</span></td></tr>
              <tr><td>Declared value</td><td><span className="mono">{targetDisplayValue(target)}</span></td></tr>
              <tr><td>Kind</td><td>{formatLabel(kind)}</td></tr>
              <tr><td>Declaration source</td><td>{plainCheckName(targetDeclarationProvenanceLabel(target))}</td></tr>
              <tr><td>Ownership method</td><td><span className="mono">{ownershipMethodText(verification)}</span></td></tr>
              <tr><td>Target group</td><td>{targetGroupId ? <a className="td-inline-link" href={buildDetailHref('target-group-detail', targetGroupId)}>{targetGroupName}</a> : 'None'}</td></tr>
              {detail.loa ? <tr><td>Group LOA</td><td>{formatLabel(getString(detail.loa, ['state'], 'Not reported'))}</td></tr> : null}
            </tbody>
          </table>
        </div>
      </section>

      <ConfirmModal
        open={review !== null}
        title={review?.mode === 'detect'
          ? `Detect WAF and CDN on ${targetDisplayValue(target)}?`
          : review?.mode === 'all'
            ? `Start ${runAll.length} checks on ${targetDisplayValue(target)}?`
            : `Start ${selectedRow?.name ?? 'this check'} on ${targetDisplayValue(target)}?`}
        description={(
          <div className="stack-tight scan-review">
            {review?.mode === 'detect' ? (
              <>
                <p>One bounded fingerprint run against this exact target: DNS resolution plus benign HTTP requests from the signed worker.</p>
                <p>Upper bound: {Number.isFinite(Number((edgeCheck?.probe_profile as DataItem | undefined)?.max_requests)) ? `${Number((edgeCheck!.probe_profile as DataItem).max_requests)} requests` : 'not recorded in the catalog'}. Ownership: {ownershipDone ? 'verified' : 'not verified'}.</p>
                <p>It identifies providers only. It does not test blocking or capacity.</p>
              </>
            ) : review?.mode === 'all' ? (
              <>
                <p><strong>{runAll.length} bounded external checks</strong> across {runAllCategoryCount} categories, at most {runAllRequestBound} probe requests in total.</p>
                <p>They run one at a time inside your safe-run limits; if an hourly limit is reached the run pauses and shows when it resumes. Other runs in this group wait until it finishes, and you can stop it at any time.</p>
                <p>The server re-checks ownership, safe windows, rate and concurrency gates when you start.</p>
              </>
            ) : (
              <>
                <dl className="td-review-list">
                  <div><dt>Target</dt><dd className="mono">{targetDisplayValue(target)}</dd></div>
                  <div><dt>Check</dt><dd>{selectedRow?.name ?? 'Not selected'} <span className="mono">{effectiveSelectedCheckId}</span></dd></div>
                  <div><dt>Upper bound</dt><dd>{selectedBound !== null ? `${selectedBound} request${selectedBound === 1 ? '' : 's'}` : 'Not recorded in the catalog'}{selectedRow?.timeoutMs ? `, ${selectedRow.timeoutMs} ms timeout` : ''}</dd></div>
                  <div><dt>Ownership</dt><dd>{ownershipDone ? 'Verified' : 'Not verified'}</dd></div>
                </dl>
                <p>The server re-checks ownership, safe windows, rate and concurrency gates when you start. A bounded check does not measure volumetric capacity.</p>
              </>
            )}
          </div>
        )}
        confirmLabel={review?.mode === 'detect' ? 'Start detection' : review?.mode === 'all' ? 'Start all checks' : 'Start check'}
        confirmTone="default"
        busy={busy === 'run' || busy === 'run-all'}
        onCancel={() => setReview(null)}
        onConfirm={() => void startReviewed()}
      />
      <ConfirmModal
        open={stopSingleRun !== null}
        title={`Stop ${stopSingleRun?.name || 'this check'}?`}
        description={scanActive ? 'This stops only this check. The remaining checks in the validation batch continue. Use Stop validation to stop the whole batch.' : 'The worker stops further attempts and retains recorded activity. A bounded request already in flight may finish.'}
        confirmLabel="Stop check" confirmTone="danger" busy={busy === 'stop-check'}
        onCancel={() => setStopSingleRun(null)} onConfirm={() => void stopSingleCheck()}
      />
      <CancelScanDialog
        scan={stopOpen ? scan : null}
        config={config}
        session={session}
        onClose={() => setStopOpen(false)}
        onCancelled={(result) => {
          setStopOpen(false);
          setScan(result);
          setBanner('Multi-check run stopped. Finished results are kept.');
          void loadTargetActivity();
        }}
      />
    </div>
  );
}
