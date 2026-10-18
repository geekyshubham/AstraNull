import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import {
  ChevronDown,
  ChevronUp,
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
  fetchTargetOriginBindings,
  populateTargetDetail,
  verifyOwnershipChallenge,
  type DeclarationDraft,
  type ObservationHistory,
  type OwnershipChallenge,
  type TargetDetailPayload,
} from '../lib/target-detail-api';
import { hasEvidenceBackedVerdict, publishedRunVerdict } from '../lib/run-verdict';
import { findingStatus, fixVerifiedBasisHint, isFindingOpen } from '../lib/finding-lifecycle.mjs';
// @ts-ignore Plain ESM keeps truthfulness rules executable in focused node tests.
import { addTargetTag, apiErrorCode, demoTenantSignal, edgeDetectionReasonExplanation, isActiveDnsChallenge, isTargetRunEligible, ownershipMethodLabel, ownershipStepStatus, removeTargetTag, targetDeclarationProvenanceLabel, targetDisplayValue, uniqueRecentRuns, uniqueVerificationHistory } from '../lib/target-detail.mjs';
import { VerifyChip, resolveTargetVerificationProvenance } from '../lib/verify-chip';
import { buildDetailHref, getRouteParam, replaceRouteParams } from '../lib/route-params';
import type { AcceptedExecution, DataItem, PortalConfig, Session } from '../lib/types';
import { countLabel, formatDate, formatSeverityLabel, pluralize } from '../lib/utils';
import { severityTone } from '../lib/severity-tone';
import { AnchorButton, Button } from '../components/ui/button';
import { EmptyState } from '../components/ui/empty-state';
import { emptyStateFromApi } from '../lib/empty-from-api';
import { DataTable, type TableColumn } from '../components/ui/table';
import { Badge, type BadgeProps } from '../components/ui/badge';
import { NotTestedBadge } from '../components/runs/not-tested-note';
import { requiredInputMissing } from '../lib/missing-input.mjs';
import { Tabs } from '../components/ui/tabs';
import { Toast } from '../components/ui/toast';
import { canStartRun } from '../lib/run-permissions.mjs';
import { requestJson, sessionIdentity } from '../lib/api';
import { activityItemsToEvents } from '../lib/recorded-activity.mjs';
import { useRecordedActivity } from '../components/evidence/use-recorded-activity';
import { prefersReducedMotion } from '../lib/motion';
import { apiErrorMessage } from '../lib/error-messages';
import { ConfirmModal } from '../lib/crud-ui';
import { MAX_SCAN_CHECKS, isScanActive, scanErrorMessage } from '../lib/validation-scan.mjs';
import {
  EDGE_DETECTION_CHECK_ID,
  buildCheckRows,
  countRowStatuses,
  edgeDetectionPhase,
  markerEffectiveness,
  providerFamilyRows,
  recommendedStarterRow,
  assessEdgeEfficacy,
  wafRuleEnforcement,
  customCanaryMembers,
  retainedCoveragePairs,
  assessmentChecks,
  targetCheckRequirement,
  targetCheckAvailability,
  individualChecks,
  withTargetRunnableChecks,
  targetTabFromParam,
  validationScansPathForTarget,
  type CheckRow,
  type ProviderFamilyRow,
  type TargetTab,
} from '../lib/domain-checks.mjs';
import { CheckQueue, ProviderObservations, rowImpact } from '../components/targets/domain-protection';
import { CHECK_IMPACT_CLASSES, classifyCheckImpact } from '../lib/check-classification.mjs';
import { ControlDeclarations, normalizePerspectives, type OriginRelationSummary, type ProbePerspective } from '../components/targets/control-declarations';
import { RuleCoveragePanel } from '../components/rule-coverage/rule-coverage';
import { controlsHref, prerequisiteCta, prerequisiteSection, prerequisiteTone, targetRunnableIndex, type CheckPrerequisite } from '../lib/control-declarations.mjs';
import { VERSION_GAP_COPY } from '../lib/probe-evidence.mjs';
import { TargetChangesHistory } from '../components/targets/target-history';
import { TargetSubdomains } from '../components/targets/target-subdomains';
import { InitialEdgeStatus } from '../components/targets/initial-edge-status';
import { TargetAuthorization } from '../components/targets/target-authorization';
import { OriginRelations } from '../components/targets/origin-relations';
import { OriginExposure } from '../components/targets/origin-exposure';
import { DeclaredEntryPaths, FirewallChangeComparison } from '../components/targets/entry-paths';
import { ProbeActivity } from '../components/targets/probe-activity';
import { OwnershipProof } from '../components/targets/ownership-proof';
import { DECLARATION_LIMITS, validateDeclarationDraft } from '../lib/domain-checks.mjs';
import { CancelScanDialog } from '../components/runs/validation-scans-table';
import { useInspectorRef, useOpenInspector } from '../components/evidence/use-inspector';
import { useInteractionHold, useStableList } from '../components/evidence/use-stable-list';
import { navScopeKey } from '../lib/nav-state.mjs';
import { evidenceModePresentation, plainCheckName, plainFindingTitle, plainVerdictLabel, plainVerificationLabel } from '../lib/plain-language.mjs';
import { checkPresentation } from '../lib/check-presentation.mjs';
import { PortalUnavailablePage } from './public-pages';
import { DetailBackLink } from '../components/layout/detail-back-link';
import { useEntityDocumentTitle } from '../components/layout/app-shell';
import './target-detail-view.css';

type StatTone = NonNullable<BadgeProps['tone']>;
type EdgeLocalState = '' | 'pending' | 'blocked' | 'error';
type ReviewPlan = { mode: 'single'; checkId: string } | { mode: 'selected'; checkIds: string[] } | { mode: 'all' } | { mode: 'detect' } | null;

const TARGET_RUNS_LIMIT = 100;
const EDGE_POLL_MS = 4_000;
const EDGE_POLL_MAX_MS = 3 * 60 * 1000;
const EDGE_BLOCKED_RETRY_MS = 15_000;
const EDGE_BLOCKED_MAX_RETRIES = 20;
const DNS_RECHECK_MS = 30_000;
const DNS_RECHECK_MAX_MS = 15 * 60 * 1000;
const CLOCK_TICK_MS = 60_000;
const DNS_TXT_KINDS = new Set(['fqdn', 'url']);
const OWNERSHIP_LOCKED_REASON = 'Prove ownership first. External checks stay blocked until this target is verified.';
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
  invalid_or_unresolved_evidence: 'Cited evidence could not be verified',
  not_finalized: 'Run not finalized',
  ...VERSION_GAP_COPY,
};

const DIMENSION_LABELS: Record<string, string> = {
  application: 'Application',
  origin: 'Origin lockdown',
  network: 'Network and transport',
  dns: 'DNS',
  operations: 'Operations',
  other: 'Other',
};

const DIMENSION_NOT_ASSESSABLE: Record<string, string> = {
  application: 'No check that can pass or fail fits this target kind.',
  origin: 'Declare an origin binding and origin lockdown first; until then direct reachability is recorded, not scored.',
  network: 'Network checks can only report a violation of a rule you declared, never a pass, so none is scored here.',
  dns: 'No DNS check that can pass or fail fits this target kind.',
  operations: 'Operational readiness is declared, not probed.',
  other: 'Nothing here can be scored from outside-in evidence.',
};

type DeclarationsLoad = { scope: string; status: 'loading' | 'ready' | 'error'; doc: DataItem | null; error: string };

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

function formatLabel(value: unknown, fallback = 'Not reported') {
  const trimmed = typeof value === 'string' ? value.trim() : '';
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
  if (['running', 'collecting'].includes(key)) return 'warn';
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

function TagEditor({ tags, canEdit, onChange }: { tags: string[]; canEdit: boolean; onChange: (next: string[]) => Promise<void> }) {
  const [draft, setDraft] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [adding, setAdding] = useState(false);
  const showForm = adding || Boolean(draft) || Boolean(error);

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
      {canEdit && !showForm ? (
        <div className="td-tag-form">
          <Button size="sm" variant="ghost" onClick={() => setAdding(true)}><Plus size={14} aria-hidden="true" />Add tag</Button>
        </div>
      ) : null}
      {canEdit && showForm ? (
        <div className="td-tag-form">
          <input
            autoFocus={adding && !draft}
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
              if (event.key === 'Escape' && !draft) { event.preventDefault(); setError(''); setAdding(false); }
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
    return { text: value ? formatLabel(value) : 'Not recorded', source: status === 'inherited' ? 'inherited' : 'declared' };
  };
  const inherited = (key: string) => getString(declaration, [key], '') === 'inherited' ? 'inherited' : '';
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
      <p className="td-muted">Recorded as your declaration and audited. Only fields you change are saved; untouched fields keep their inherited values. It never grants scope and never changes the target value or kind.</p>
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
  wafEdgeEnabled = false,
  protectionValidationEnabled = false,
  deploymentFeatures = null,
  onRefresh,
}: {
  entityId: string;
  config: PortalConfig;
  session: Session;
  checks: DataItem[];
  /** Tenant deployment feature `waf_posture`; WAF/CDN detection routes 404 without it. */
  wafEdgeEnabled?: boolean;
  /** Tenant deployment feature `protection_validation`; entry-path and firewall change routes 404 without it. */
  protectionValidationEnabled?: boolean;
  /** Tenant deployment features as served; a `demo_tenant` flag lets demo tenants follow the server's runnability answer. */
  deploymentFeatures?: DataItem | null;
  onRefresh: () => Promise<void>;
}) {
  const executionScope = `${sessionIdentity(session)}|${entityId}`;
  const scopeRef = useRef(executionScope);
  scopeRef.current = executionScope;
  const [storedDetail, setDetail] = useState<TargetDetailPayload | null>(null);
  const [detailScope, setDetailScope] = useState('');
  const detail = detailScope === executionScope ? storedDetail : null;
  const [acceptedRun, setAcceptedRun] = useState<{ scope: string; id: string; checkId: string; record: DataItem } | null>(null);
  const [busy, setBusy] = useState('');
  const [error, setError] = useState('');
  const [banner, setBanner] = useState('');
  const [selectedCheckId, setSelectedCheckId] = useState(() => getRouteParam('check'));
  const [tab, setTabState] = useState<TargetTab>(readTab);
  const [scan, setScan] = useState<DataItem | null>(null);
  const [scanActivity, setScanActivity] = useState<DataItem[]>([]);
  const [targetRuns, setTargetRuns] = useState<DataItem[]>([]);
  const [runsError, setRunsError] = useState('');
  const [catalogLoad, setCatalogLoad] = useState<{ scope: string; items: DataItem[] | null; error: string }>({ scope: '', items: null, error: '' });
  const [catalogReload, setCatalogReload] = useState(0);
  const fullCatalog = catalogLoad.scope === executionScope ? catalogLoad.items : null;
  const catalogError = catalogLoad.scope === executionScope ? catalogLoad.error : '';
  const [edgeLocal, setEdgeLocal] = useState<EdgeLocalState>('');
  const [edgeError, setEdgeError] = useState('');
  const [edgeReason, setEdgeReason] = useState('');
  const [review, setReview] = useState<ReviewPlan>(null);
  const [stopOpen, setStopOpen] = useState(false);
  const [stopSingleRun, setStopSingleRun] = useState<{ id: string; name: string } | null>(null);
  const [editingContext, setEditingContext] = useState(false);
  const [dnsWatchStartedAt, setDnsWatchStartedAt] = useState(0);
  const [dnsWatchStopped, setDnsWatchStopped] = useState(false);
  const [ownershipError, setOwnershipError] = useState('');
  const [runSelection, setRunSelection] = useState<string[]>([]);
  const [clock, setClock] = useState(() => Date.now());
  const [declarationsLoad, setDeclarationsLoad] = useState<DeclarationsLoad>({ scope: '', status: 'loading', doc: null, error: '' });
  const [perspectives, setPerspectives] = useState<ProbePerspective[]>([]);
  const [perspectivesError, setPerspectivesError] = useState('');
  const [controlsReload, setControlsReload] = useState(0);
  const [coverageReload, setCoverageReload] = useState(0);
  const controlsDirtyRef = useRef(false);
  const edgeRetriesRef = useRef(0);
  const loadGeneration = useRef(0);
  const openInspector = useOpenInspector();
  const inspected = useInspectorRef();

  const reload = useCallback(async () => {
    const generation = loadGeneration.current;
    const refreshed = await populateTargetDetail(config, session, entityId);
    if (generation === loadGeneration.current && scopeRef.current === executionScope) { setDetail(refreshed); setDetailScope(executionScope); }
    return refreshed;
  }, [config, session, entityId, executionScope]);

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
      if (generation === loadGeneration.current && scopeRef.current === executionScope) { setDetail(payload); setDetailScope(executionScope); }
    });
  }, [config, session, entityId, executionScope]);

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

  const setTab = useCallback((next: TargetTab) => {
    if (controlsDirtyRef.current && next !== 'controls' && !window.confirm('You have unsaved control declarations. Leave without saving?')) return;
    if (next !== 'controls') controlsDirtyRef.current = false;
    setTabState(next);
    replaceRouteParams({ tab: next === 'overview' ? null : next, section: null });
  }, []);
  const onControlsDirty = useCallback((dirty: boolean) => { controlsDirtyRef.current = dirty; }, []);

  const selectCheck = useCallback((checkId: string) => {
    setSelectedCheckId(checkId);
    replaceRouteParams({ check: checkId || null });
  }, []);

  const target = detail?.target ?? null;
  const verification = detail?.verification ?? null;
  const challenge: OwnershipChallenge = detail?.ownership_challenge ?? null;
  const tags = detail?.tags ?? [];
  const kind = getString(target, ['kind'], 'unknown');
  const eligibility = getString(target, ['eligibility'], 'unknown');
  const verificationState = getString(verification, ['state'], getString(target, ['verification_state'], 'unverified'));
  const targetEligible = isTargetRunEligible(eligibility, verificationState);
  const rawProvenance = resolveTargetVerificationProvenance(target, verification);
  const provenance = /agent/i.test(rawProvenance) ? `Recorded ownership evidence for ${verificationState}.` : rawProvenance;
  const canWrite = canStartRun(session.role);
  const canStartBoundedRun = canStartRun(session.role);
  useEntityDocumentTitle(target ? targetDisplayValue(target) : undefined);

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
  const deduplicatedOpenFindings = useMemo(() => deduplicatedFindings.filter((item) => isFindingOpen(item.representative)), [deduplicatedFindings]);
  const expandedFindingHistory = useMemo(
    () => deduplicatedFindings.find((item) => item.representativeId === expandedFindingHistoryId) ?? null,
    [deduplicatedFindings, expandedFindingHistoryId]
  );
  const ownershipHistory = buildOwnershipHistory(verification);
  const declaration = detail?.declaration ?? null;
  const declared = declarationSummary(declaration);

  const declarationsDoc = declarationsLoad.scope === executionScope && declarationsLoad.status === 'ready' ? declarationsLoad.doc : null;
  const serverRunnableIndex = useMemo(() => targetRunnableIndex(fullCatalog), [fullCatalog]);
  const demoTenant = demoTenantSignal({ verification, deploymentFeatures });
  const prerequisiteContext = useMemo(() => ({
    declarations: declarationsDoc ?? undefined,
    perspectiveCount: perspectives.length,
    serverRunnableIndex,
    serverSuppliesInput: demoTenant,
  }), [declarationsDoc, perspectives.length, serverRunnableIndex, demoTenant]);
  const targetChecks = useMemo(() => withTargetRunnableChecks(checks, fullCatalog, { serverSuppliesInput: demoTenant }), [checks, fullCatalog, demoTenant]);
  const runAll = useMemo(() => (target ? assessmentChecks(targetChecks, target, prerequisiteContext) as DataItem[] : []), [targetChecks, target, prerequisiteContext]);
  const remainingCatalog = useMemo(() => (fullCatalog ?? []).filter((check) => targetCheckRequirement(check, target, prerequisiteContext)), [fullCatalog, target, prerequisiteContext]);
  const selectableChecks = useMemo(() => target ? individualChecks(targetChecks, target, prerequisiteContext) as DataItem[] : [], [targetChecks, target, prerequisiteContext]);
  const inventoryChecks = useMemo(() => fullCatalog ?? selectableChecks, [fullCatalog, selectableChecks]);
  const scopedAcceptedRun = acceptedRun?.scope === executionScope ? acceptedRun : null;
  const checkRows = useMemo(() => {
    const rows = buildCheckRows({ checks: inventoryChecks, scan, runs: targetRuns, coverage: detail?.coverage }) as CheckRow[];
    if (!scopedAcceptedRun) return rows;
    // Pin the returned execution, not a newest-list guess or a fabricated sorting timestamp.
    const record = targetRuns.find((run) => run.id === scopedAcceptedRun.id) ?? scopedAcceptedRun.record;
    const exact = buildCheckRows({ checks: inventoryChecks.filter((check) => check.check_id === scopedAcceptedRun.checkId), runs: [record], coverage: detail?.coverage })[0] as CheckRow | undefined;
    return exact ? rows.map((row) => row.checkId === exact.checkId ? exact : row) : rows;
  }, [inventoryChecks, scan, targetRuns, scopedAcceptedRun, detail?.coverage]);
  const selectableIds = useMemo(() => new Set(selectableChecks.map((check) => getString(check, ['check_id'], ''))), [selectableChecks]);
  const selectableRows = useMemo(() => checkRows.filter((row) => selectableIds.has(row.checkId)), [checkRows, selectableIds]);
  const rowCounts = useMemo(() => countRowStatuses(selectableRows) as Record<string, number>, [selectableRows]);
  const prerequisites = useMemo(() => Object.fromEntries(inventoryChecks.map((check) => [
    getString(check, ['check_id'], ''),
    targetCheckAvailability(check, target, prerequisiteContext),
  ])) as Record<string, CheckPrerequisite>, [inventoryChecks, prerequisiteContext, target]);
  const runnableIds = useMemo(() => new Set(selectableChecks.map((check) => getString(check, ['check_id'], '')).filter((id) => prerequisites[id]?.state === 'ready')), [selectableChecks, prerequisites]);
  const recommendedRow = useMemo(() => recommendedStarterRow(checkRows.filter((row) => runnableIds.has(row.checkId))), [checkRows, runnableIds]);
  const effectiveSelectedCheckId = checkRows.some((row) => row.checkId === selectedCheckId) ? selectedCheckId : '';
  const selectedCheckMissing = Boolean(selectedCheckId) && !effectiveSelectedCheckId && checkRows.length > 0;
  const selectedRow = checkRows.find((row) => row.checkId === effectiveSelectedCheckId) ?? null;
  const checkNameById = useMemo(
    () => new Map(inventoryChecks.map((check) => [getString(check, ['check_id', 'id'], ''), checkPresentation(check).name])),
    [inventoryChecks],
  );
  const displayCheckName = (checkId: string) => checkNameById.get(checkId) || checkId || 'Unnamed check';

  const edgeDetection = detail?.edge_detection ?? null;
  const edgeRequest = detail?.edge_detection_request ?? null;
  const profileInput = { protection_profile: detail?.protection_profile ?? null, edge_detection: edgeDetection };
  const providerRows = useMemo(() => providerFamilyRows(profileInput), [detail?.protection_profile, edgeDetection]); // eslint-disable-line react-hooks/exhaustive-deps
  const effectiveness = useMemo(() => markerEffectiveness(profileInput), [detail?.protection_profile, edgeDetection]); // eslint-disable-line react-hooks/exhaustive-deps
  const scanActive = isScanActive(scan);
  const activeStandalone = targetRuns.find((run) => ['running', 'collecting', 'planned'].includes(getString(run, ['status'], ''))) ?? null;
  const activeCheckRow = checkRows.find((row) => row.status === 'running' && row.runId) ?? null;
  const currentScanStep = Array.isArray(scan?.steps) ? (scan.steps as DataItem[]).find((step) => ['running', 'collecting', 'starting'].includes(getString(step, ['status'], '')) && getString(step, ['test_run_id'], '')) ?? null : null;
  const activityRow = selectedRow ?? activeCheckRow ?? null;
  const activityPinnedRow = selectedRow?.runId ? selectedRow : null;
  const exactAcceptedRun = acceptedRun?.scope === executionScope && (!selectedRow || selectedRow.checkId === acceptedRun.checkId) ? acceptedRun : null;
  const activityRunId = exactAcceptedRun?.id || (activityPinnedRow ? activityPinnedRow.runId : getString(currentScanStep, ['test_run_id'], '') || getString(activeStandalone, ['id'], '') || activityRow?.runId || '');
  const activityRunning = exactAcceptedRun ? ['planned', 'running', 'collecting'].includes(getString(targetRuns.find((run) => run.id === exactAcceptedRun.id), ['status'], getString(exactAcceptedRun.record, ['status'], ''))) : activityPinnedRow ? activityPinnedRow.status === 'running' : Boolean(currentScanStep || activeStandalone);
  const activityCheckName = exactAcceptedRun ? displayCheckName(exactAcceptedRun.checkId) : activityPinnedRow?.name || (currentScanStep ? displayCheckName(getString(currentScanStep, ['check_id'], '')) : activeStandalone ? displayCheckName(getString(activeStandalone, ['check_id'], '')) : activityRow?.name || '');
  const showActivity = Boolean(selectedRow || exactAcceptedRun || currentScanStep || activeStandalone || activeCheckRow);
  const inspectingActivityRun = Boolean(
    (inspected?.entry === 'check_result' && activityRunId && inspected.test_run_id === activityRunId)
    || (inspected?.entry === 'validation_scan' && scanActive && inspected.scan_id && inspected.scan_id === getString(scan, ['id'], '')),
  );
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
  const ownershipStep = ownershipStepStatus(verificationState, challenge, clock) as { tone: StatTone; label: string; done: boolean };
  const ownershipDone = ownershipStep.done;
  const challengeState = getString(challenge as unknown as DataItem, ['state'], '');
  const edgeCheck = checks.find((check) => getString(check, ['check_id', 'id'], '') === EDGE_DETECTION_CHECK_ID) ?? null;

  const loadTargetActivity = useCallback(async () => {
    if (!entityId) return;
    const generation = loadGeneration.current;
    const [scanList, runList] = await Promise.all([
      requestJson(config, session, validationScansPathForTarget(entityId)).catch(() => null) as Promise<DataItem | null>,
      requestJson(config, session, `/v1/test-runs?target_id=${encodeURIComponent(entityId)}&limit=${TARGET_RUNS_LIMIT}`)
        .then((value) => { if (generation === loadGeneration.current) setRunsError(''); return value; })
        .catch((err) => { if (generation === loadGeneration.current) setRunsError(apiErrorMessage(err, 'Recorded check results could not load.')); return null; }) as Promise<DataItem | null>,
    ]);
    if (generation !== loadGeneration.current) return;
    if (scanList && Array.isArray(scanList.items)) {
      const activeScan = (scanList.items[0] as DataItem | undefined) ?? null;
      setScan(activeScan);
      // The shared exact-ID reader supplies activity and final pages for this assessment.
    }
    if (runList && Array.isArray(runList.items)) setTargetRuns(runList.items as DataItem[]);
  }, [config, session, entityId]);

  useEffect(() => {
    setScan(null);
    setScanActivity([]);
    setTargetRuns([]);
    setEdgeLocal('');
    setEdgeError('');
    setEdgeReason('');
    setDnsWatchStartedAt(0);
    setDnsWatchStopped(false);
    setOwnershipError('');
    setRunSelection([]);
    setStopSingleRun(null);
    setAcceptedRun(null);
    setReview(null);
    setStopOpen(false);
    setError(''); setBanner('');
    edgeRetriesRef.current = 0;
  }, [executionScope]);

  const declarationsRevision = declarationsDoc ? Number(declarationsDoc.revision ?? 0) : -1;
  useEffect(() => {
    if (!entityId) return undefined;
    let stopped = false;
    const scope = executionScope;
    setCatalogLoad({ scope, items: null, error: '' });
    void requestJson(config, session, `/v1/checks?scope=all&target_id=${encodeURIComponent(entityId)}`).then((payload) => {
      if (!Array.isArray((payload as DataItem)?.items)) throw new Error('The full check catalog returned an invalid response.');
      if (!stopped && scopeRef.current === scope) setCatalogLoad({ scope, items: (payload as DataItem).items as DataItem[], error: '' });
    }).catch((err) => { if (!stopped && scopeRef.current === scope) setCatalogLoad({ scope, items: null, error: apiErrorMessage(err, 'The full check catalog could not load.') }); });
    return () => { stopped = true; };
  }, [config, session, entityId, executionScope, declarationsRevision, catalogReload]);

  useEffect(() => { void loadTargetActivity(); }, [loadTargetActivity]);

  useEffect(() => {
    if (!entityId) return undefined;
    let stopped = false;
    const scope = executionScope;
    setDeclarationsLoad((current) => ({ scope, status: current.scope === scope && current.status === 'ready' ? 'ready' : 'loading', doc: current.scope === scope ? current.doc : null, error: '' }));
    requestJson(config, session, `/v1/targets/${encodeURIComponent(entityId)}/control-declarations`)
      .then((payload) => { if (!stopped) setDeclarationsLoad({ scope, status: 'ready', doc: asDataItem(payload) ?? { version: 1 }, error: '' }); })
      .catch((err) => { if (!stopped) setDeclarationsLoad({ scope, status: 'error', doc: null, error: apiErrorMessage(err, 'Control declarations could not load.') }); });
    requestJson(config, session, '/v1/probe-perspectives')
      .then((payload) => { if (!stopped) { setPerspectives(normalizePerspectives(payload)); setPerspectivesError(''); } })
      .catch((err) => { if (!stopped) { setPerspectives([]); setPerspectivesError(apiErrorMessage(err, 'Probe perspectives could not load.')); } });
    return () => { stopped = true; };
  }, [config, session, entityId, executionScope, controlsReload]);

  const [originRelations, setOriginRelations] = useState<OriginRelationSummary>({ state: 'loading', active: 0 });
  useEffect(() => {
    if (!entityId || tab !== 'controls') return undefined;
    const controller = new AbortController();
    setOriginRelations({ state: 'loading', active: 0 });
    void fetchTargetOriginBindings(config, session, entityId, controller.signal).then((result) => {
      if (controller.signal.aborted) return;
      if (result.state !== 'ready') { setOriginRelations({ state: 'unavailable', active: 0 }); return; }
      const active = result.items.filter((item) => getString(item, ['status'], '') === 'active' && getString(item, ['protected_target_id'], '') === entityId).length;
      setOriginRelations({ state: 'ready', active });
    });
    return () => controller.abort();
  }, [config, session, entityId, tab, controlsReload]);

  const overviewSection = tab === 'overview' ? getRouteParam('section') : '';
  useEffect(() => {
    if (overviewSection !== 'origin-relations') return undefined;
    const frame = window.requestAnimationFrame(() => {
      const heading = document.getElementById('td-origin-relations-title');
      if (!heading) return;
      heading.scrollIntoView({ block: 'start' });
      heading.focus({ preventScroll: true });
    });
    return () => window.cancelAnimationFrame(frame);
  }, [overviewSection, target]);

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

  // Table, console and Inspector use one passive reader and retain every available page.
  const scanReader = useRecordedActivity({ config, session, kind: 'scan', id: scanId });
  const previousScanState = useRef({ id: '', active: false, fingerprint: false });
  useEffect(() => {
    const next = scanReader.record;
    if (!next || next.id !== scanId) return;
    setScan(next);
    if (scanReader.snapshot && Array.isArray(scanReader.snapshot.items)) setScanActivity(scanReader.snapshot.items as DataItem[]);
    const step = Array.isArray(next.steps) ? (next.steps as DataItem[]).find((row) => getString(row, ['check_id'], '') === EDGE_DETECTION_CHECK_ID) : null;
    const fingerprint = ACTIVE_STEP_STATUSES.has(getString(step ?? null, ['status'], ''));
    const previous = previousScanState.current;
    if (previous.id === scanId && ((previous.fingerprint && !fingerprint) || (previous.active && !isScanActive(next)))) {
      void reload().catch(() => undefined);
      void loadTargetActivity();
      void onRefresh().catch(() => undefined);
    }
    previousScanState.current = { id: scanId, active: isScanActive(next), fingerprint };
  }, [scanId, scanReader.record, scanReader.snapshot, reload, loadTargetActivity, onRefresh]);

  const selectedActivityReader = useRecordedActivity({ config, session, id: selectedRow?.runId || '' });
  const selectedRunEvents = useMemo(() => activityItemsToEvents(selectedActivityReader.snapshot) as DataItem[], [selectedActivityReader.snapshot]);

  const queueEdgeDetection = useCallback(async () => {
    if (!entityId) return;
    const generation = loadGeneration.current;
    setEdgeLocal('pending');
    setEdgeError('');
    setEdgeReason('');
    try {
      const accepted = await requestJson(config, session, '/v1/waf/edge-detection', {
        method: 'POST',
        body: { target_id: entityId },
      }) as DataItem;
      if (generation !== loadGeneration.current || scopeRef.current !== executionScope) return;
      edgeRetriesRef.current = 0;
      selectCheck(EDGE_DETECTION_CHECK_ID);
      setTab('validate');
      const detectionRequest = accepted.detection_request as DataItem | undefined;
      const runId = getString(detectionRequest, ['test_run_id'], '');
      if (runId) {
        setAcceptedRun({ scope: executionScope, id: runId, checkId: EDGE_DETECTION_CHECK_ID, record: { id: runId, check_id: EDGE_DETECTION_CHECK_ID, status: getString(detectionRequest, ['run_status'], 'planned') } });
        openInspector({ entry: 'check_result', target_id: entityId, check_id: EDGE_DETECTION_CHECK_ID, test_run_id: runId }, 'td-detect');
      }
      await reload().catch(() => undefined);
      void loadTargetActivity();
    } catch (err) {
      if (generation !== loadGeneration.current) return;
      if (apiErrorCode(err) === 'concurrent_run_blocked') {
        setEdgeLocal('blocked');
        return;
      }
      setEdgeLocal('error');
      setEdgeError(apiErrorMessage(err, 'WAF/CDN detection could not be queued.'));
    }
  }, [config, session, entityId, executionScope, loadTargetActivity, reload, selectCheck, setTab, openInspector]);

  // Only after the user explicitly started detection: wait for the target’s execution slot.
  useEffect(() => {
    if (edgeLocal !== 'blocked' || scanActive) return undefined;
    if (edgeRetriesRef.current >= EDGE_BLOCKED_MAX_RETRIES) return undefined;
    const timer = window.setTimeout(() => {
      edgeRetriesRef.current += 1;
      void queueEdgeDetection();
    }, EDGE_BLOCKED_RETRY_MS);
    return () => window.clearTimeout(timer);
  }, [edgeLocal, scanActive, queueEdgeDetection]);

  // While user-started detection is in flight, re-read the target until the result is persisted.
  useEffect(() => {
    if (!edgeEvaluating || fingerprintStepActive) return undefined;
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
          if (status && !['pending', 'planned', 'queued', 'running', 'collecting'].includes(status)) {
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
  }, [edgeEvaluating, fingerprintStepActive, loadTargetActivity, reload]);

  useEffect(() => {
    if (edgePhase !== 'no_result' || !edgeRequestRunId || !wafEdgeEnabled) return undefined;
    let cancelled = false;
    requestJson(config, session, `/v1/waf/edge-detection/${encodeURIComponent(edgeRequestRunId)}`)
      .then((payload) => { if (!cancelled) setEdgeReason(getString(payload as DataItem, ['reason'], '')); })
      .catch(() => undefined);
    return () => { cancelled = true; };
  }, [config, session, edgePhase, edgeRequestRunId, wafEdgeEnabled]);

  // The challenge lifetime is shown in minutes, so the clock only needs to tick while one is live.
  const challengeExpiresAt = challenge?.expires_at ?? '';
  useEffect(() => {
    if (ownershipDone || challengeState !== 'pending' || !challengeExpiresAt) return undefined;
    setClock(Date.now());
    const timer = window.setInterval(() => setClock(Date.now()), CLOCK_TICK_MS);
    const untilExpiry = Date.parse(challengeExpiresAt) - Date.now();
    const expiry = Number.isFinite(untilExpiry) && untilExpiry > 0 ? window.setTimeout(() => setClock(Date.now()), untilExpiry + 250) : 0;
    return () => { window.clearInterval(timer); if (expiry) window.clearTimeout(expiry); };
  }, [ownershipDone, challengeState, challengeExpiresAt]);

  // DNS re-checks run only after the user chose Check now or issued a record in this visit.
  useEffect(() => {
    if (!dnsWatchStartedAt || !canWrite || ownershipDone || !challenge?.id || !isActiveDnsChallenge(challenge, Date.now())) return undefined;
    const challengeId = challenge.id;
    const watched = challenge;
    let busyCheck = false;
    const timer = window.setInterval(() => {
      if (busyCheck) return;
      if (!isActiveDnsChallenge(watched, Date.now())) { window.clearInterval(timer); setDnsWatchStartedAt(0); setClock(Date.now()); return; }
      if (Date.now() - dnsWatchStartedAt > DNS_RECHECK_MAX_MS) { window.clearInterval(timer); setDnsWatchStartedAt(0); setDnsWatchStopped(true); return; }
      busyCheck = true;
      verifyOwnershipChallenge(config, session, entityId, challengeId)
        .then(async (result) => {
          if ((result as DataItem)?.verified === true) {
            window.clearInterval(timer);
            setDnsWatchStartedAt(0);
            setBanner('Ownership proven. You can now review and start bounded checks on this target.');
            await onRefresh().catch(() => undefined);
            await reload().catch(() => undefined);
          }
        })
        .catch((err) => {
          if (apiErrorCode(err) !== 'challenge_expired') return;
          window.clearInterval(timer);
          setDnsWatchStartedAt(0);
          setOwnershipError(apiErrorMessage(err, 'This DNS TXT value expired before it was found. Issue a new record and publish the new value.'));
          void reload().catch(() => undefined);
        })
        .finally(() => { busyCheck = false; });
    }, DNS_RECHECK_MS);
    return () => window.clearInterval(timer);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [dnsWatchStartedAt, config, session, canWrite, ownershipDone, challenge?.id, challenge?.state, challenge?.expires_at]);

  const selectedRunIds = runSelection.filter((id) => runnableIds.has(id)).slice(0, MAX_SCAN_CHECKS);
  const startCheckId = selectedRunIds.length === 1 ? selectedRunIds[0] : effectiveSelectedCheckId;
  const startRow = checkRows.find((row) => row.checkId === startCheckId) ?? null;
  const activeStandaloneName = activeStandalone ? displayCheckName(getString(activeStandalone, ['check_id'], '')) : '';
  const runAllDisabledReason = canStartBoundedRun && !targetEligible ? 'Prove ownership first.' : '';
  const assessmentIds = new Set(runAll.map((check) => getString(check, ['check_id'], '')));
  const assessmentExcludedRows = checkRows.filter((row) => !assessmentIds.has(row.checkId));
  const assessmentMissingEligible = assessmentExcludedRows.some((row) => prerequisites[row.checkId]?.state === 'ready');
  const runAllBlockedReason = !scanActive && activeStandalone
    ? `${activeStandaloneName} is running on this target. Wait for it to finish or stop it before starting all checks.`
    : fullCatalog === null
      ? 'Load the full catalog before reviewing the complete evaluation.'
      : assessmentMissingEligible
        ? 'An eligible check is missing from the evaluation plan. The complete evaluation cannot start.'
        : '';

  const reviewSlotReason = scanActive
    ? 'A scan is in progress on this target.'
    : activeStandalone
      ? `${activeStandaloneName} is running on this target. Wait for it to finish or stop it before starting another check.`
      : '';
  const startPrerequisite = startCheckId ? prerequisites[startCheckId] : undefined;
  const singleDisabledReason = !canStartBoundedRun
    ? 'Your role can inspect evidence but cannot start checks.'
    : !targetEligible
      ? OWNERSHIP_LOCKED_REASON
      : !startCheckId
        ? 'Select a check in the list first.'
        : !runnableIds.has(startCheckId)
          ? startPrerequisite?.detail || 'This check is visible for reference but cannot be started here.'
          : reviewSlotReason;

  async function startScan(checkIds: string[], name: string, submittedScope: string) {
    if (!canStartBoundedRun || !ownershipDone || !checkIds.length || checkIds.some((id) => !runnableIds.has(id))) return;
    const current = () => scopeRef.current === submittedScope;
    setBusy('run-all');
    setError('');
    setBanner('');
    try {
      const created = await requestJson(config, session, '/v1/validation-scans', {
        method: 'POST',
        body: { target_id: entityId, check_ids: checkIds, name: name.slice(0, 120) },
      }) as DataItem;
      if (!current()) return;
      setReview(null);
      setAcceptedRun(null);
      setRunSelection([]);
      setScan(created);
      const acceptedScanId = getString(created, ['id'], '');
      if (!acceptedScanId) { setError('The scan start returned no recorded ID. No other scan was substituted.'); return; }
      setTab('validate');
      openInspector({ entry: 'validation_scan', target_id: entityId, scan_id: acceptedScanId }, 'td-run-all');
      setBanner(`Queued ${checkIds.length} bounded checks. Follow progress in the Inspector.`);
    } catch (err) {
      if (!current()) return;
      setReview(null);
      setError(scanErrorMessage((err as { payload?: unknown }).payload, apiErrorMessage(err, 'The scan could not start.')));
    } finally {
      if (current()) setBusy('');
    }
  }

  async function startReviewed() {
    if (!review || !target) return;
    if (!targetEligible) { setReview(null); return; }
    const submittedScope = executionScope;
    const current = () => scopeRef.current === submittedScope;
    if (review.mode === 'detect') {
      setReview(null);
      await queueEdgeDetection();
      return;
    }
    if (!ownershipDone) { setReview(null); return; }
    if (scanActive || activeStandalone) { setReview(null); return; }
    if (review.mode === 'single') {
      if (singleDisabledReason || review.checkId !== startCheckId) return;
      const reviewedCheckId = review.checkId;
      setBusy('run');
      setError('');
      setBanner('');
      try {
        const accepted = await requestJson(config, session, '/v1/test-runs', {
          method: 'POST',
          body: { target_id: entityId, check_id: reviewedCheckId },
        }) as DataItem;
        if (!current()) return;
        setReview(null);
        const created = asDataItem(accepted.run) ?? accepted;
        const runId = getString(created, ['id'], '');
        if (!runId) { setError('The start was accepted without a recorded run ID. No historical run was substituted; refresh recorded runs.'); return; }
        if ((created.target_id && created.target_id !== entityId) || (created.check_id && created.check_id !== reviewedCheckId)) { setError('The accepted execution did not match the reviewed target/check. No other run was substituted.'); return; }
        setAcceptedRun({ scope: submittedScope, id: runId, checkId: reviewedCheckId, record: created });
        setRunSelection([]);
        if (reviewedCheckId !== effectiveSelectedCheckId) selectCheck(reviewedCheckId);
        setTab('validate');
        openInspector({ entry: 'check_result', target_id: entityId, check_id: reviewedCheckId, test_run_id: runId }, `check-start-${reviewedCheckId}`);
        setBanner(`${displayCheckName(reviewedCheckId)} started. Follow its progress and evidence in the Inspector.`);
        void loadTargetActivity();
        void reload().catch(() => undefined);
        void onRefresh().catch(() => undefined);
      } catch (err) {
        if (!current()) return;
        setReview(null);
        setError(apiErrorMessage(err, 'The check could not start.'));
      } finally {
        if (current()) setBusy('');
      }
      return;
    }
    if (review.mode === 'selected') {
      const checkIds = review.checkIds.filter((id) => runnableIds.has(id)).slice(0, MAX_SCAN_CHECKS);
      if (checkIds.length < 2 || checkIds.length !== review.checkIds.length) { setReview(null); setError('Check availability changed. Review your selection again before starting.'); return; }
      await startScan(checkIds, `Selected checks · ${targetDisplayValue(target)}`, submittedScope);
      return;
    }
    if (runAllBlockedReason) { setReview(null); setError(runAllBlockedReason); return; }
    await startScan(
      runAll.map((check) => getString(check, ['check_id'], '')).filter(Boolean),
      `All compatible checks · ${targetDisplayValue(target)}`,
      submittedScope,
    );
  }

  const runAllRequestBound = runAll.reduce((total, check) => {
    const max = Number((check.probe_profile as DataItem | undefined)?.max_requests);
    return total + (Number.isFinite(max) ? max : 0);
  }, 0);
  const runAllCategoryCount = new Set(checkRows.filter((row) => runAll.some((check) => check.check_id === row.checkId)).map((row) => row.category.id)).size;
  const reviewSelectedIds = review?.mode === 'selected' ? review.checkIds.filter((id) => runnableIds.has(id)) : [];
  const reviewSelectedRows = checkRows.filter((row) => reviewSelectedIds.includes(row.checkId));
  const selectedRequestBound = reviewSelectedRows.reduce((total, row) => total + (row.maxRequests ?? 0), 0);
  const selectedUnbounded = reviewSelectedRows.filter((row) => row.maxRequests === null).length;
  const selectedObservationCount = reviewSelectedRows.filter((row) => !row.readinessCapable).length;
  const selectedCategoryCount = new Set(reviewSelectedRows.map((row) => row.category.id)).size;
  const selectedInvasiveCount = reviewSelectedRows.filter((row) => rowImpact(row) === 'invasive').length;
  const detectMax = (edgeCheck?.probe_profile as DataItem | undefined)?.max_requests;
  const detectBound = detectMax === null || detectMax === undefined || detectMax === '' || !Number.isFinite(Number(detectMax)) ? null : Number(detectMax);

  async function stopSingleCheck() {
    if (!stopSingleRun) return;
    setBusy('stop-check'); setError('');
    try {
      await requestJson(config, session, `/v1/test-runs/${encodeURIComponent(stopSingleRun.id)}/cancel`, {
        method: 'POST', body: { reason: 'Stopped from target execution activity' },
      });
      setStopSingleRun(null); setBanner('Stop requested. Recorded activity and results are kept; worker acknowledgment is shown separately.');
      await loadTargetActivity(); await reload();
    } catch (reason) { setError(apiErrorMessage(reason, 'The check could not stop. Refresh its current state.')); }
    finally { setBusy(''); }
  }

  function openStopCheck(row: CheckRow) { if (row.runId) setStopSingleRun({ id: row.runId, name: row.name }); }

  async function saveTags(next: string[]) {
    if (!target) return;
    await patchTargetTags(config, session, entityId, next);
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
    setOwnershipError('');
    setDnsWatchStopped(false);
    try {
      await issueOwnershipChallenge(config, session, entityId);
      setDnsWatchStartedAt(0);
      setBanner('DNS TXT record issued. Add it at your DNS provider, then choose Check now.');
      await reload();
    } catch (err) {
      setOwnershipError(apiErrorMessage(err, 'Could not issue a DNS TXT record.'));
    } finally {
      setBusy('');
    }
  }

  async function checkOwnership() {
    if (!challenge?.id) return;
    setBusy('verify');
    setError('');
    setBanner('');
    setOwnershipError('');
    setDnsWatchStopped(false);
    try {
      const result = await verifyOwnershipChallenge(config, session, entityId, challenge.id) as DataItem;
      const verified = result?.verified === true || getString(asDataItem(result.challenge), ['state']) === 'resolved';
      if (verified) {
        setDnsWatchStartedAt(0);
        setBanner('Ownership proven. You can now review and start bounded checks on this target.');
      } else {
        setDnsWatchStartedAt(Date.now());
        setBanner('The DNS TXT record was not found yet. DNS can take a few minutes; this page re-checks every 30 seconds while the record is valid and the page stays open.');
      }
      await onRefresh();
      await reload();
    } catch (err) {
      setOwnershipError(apiErrorMessage(err, 'Could not check the DNS record.'));
      if (apiErrorCode(err) === 'challenge_expired') {
        setDnsWatchStartedAt(0);
        setClock(Date.now());
        void reload().catch(() => undefined);
      }
    } finally {
      setBusy('');
    }
  }

  function onReviewedExecutionStarted(text: string, execution?: AcceptedExecution) {
    if (scopeRef.current !== executionScope) return;
    setBanner(text);
    if (execution) {
      const { runId, checkId, targetId, record } = execution;
      if (!runId || !checkId || !targetId) { setError('The accepted execution identity was incomplete. No historical run was substituted.'); return; }
      if (targetId === entityId) setAcceptedRun({ scope: executionScope, id: runId, checkId, record: record ?? { id: runId, check_id: checkId, target_id: targetId } });
      openInspector({ entry: 'check_result', target_id: targetId, check_id: checkId, test_run_id: runId }, `reviewed-start-${runId}`);
      void loadTargetActivity();
    }
    void reload().catch(() => undefined);
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
      <OwnershipProof
        kind={kind}
        hostname={targetDisplayValue(target)}
        challenge={challenge}
        now={clock}
        compact={compact}
        panelId={compact ? 'td-validate-ownership' : 'td-ownership-panel'}
        canWrite={canWrite}
        busy={busy}
        error={ownershipError}
        watching={Boolean(dnsWatchStartedAt)}
        watchStopped={dnsWatchStopped}
        onIssue={() => void issueOwnership()}
        onCheck={() => void checkOwnership()}
      />
    );
  }

  function focusOwnership(panelId: string) {
    window.requestAnimationFrame(() => {
      const panel = document.getElementById(panelId);
      if (!panel) return;
      panel.scrollIntoView({ behavior: prefersReducedMotion() ? 'auto' : 'smooth', block: 'center' });
      const action = Array.from(panel.querySelectorAll<HTMLButtonElement>('button:not([disabled])'))
        .find((button) => /^(Check now|Issue DNS TXT record|Issue a new record)$/.test(button.textContent?.trim() ?? ''));
      (action ?? panel).focus({ preventScroll: true });
    });
  }

  function proveOwnership() {
    setTab('overview');
    window.requestAnimationFrame(() => {
      const heading = document.getElementById('td-next-title');
      if (!heading) return;
      heading.scrollIntoView({ behavior: prefersReducedMotion() ? 'auto' : 'smooth', block: 'start' });
      const panel = document.getElementById('td-ownership-panel');
      const action = panel
        ? Array.from(panel.querySelectorAll<HTMLButtonElement>('button:not([disabled])')).find((button) => /^(Check now|Issue DNS TXT record|Issue a new record)$/.test(button.textContent?.trim() ?? ''))
        : null;
      (action ?? heading).focus({ preventScroll: true });
    });
  }

  const lastCheckAt = (() => {
    const recorded = getString(target, ['last_validation_at', 'last_validated_at'], '');
    if (recorded) return recorded;
    let newest = Number.NEGATIVE_INFINITY;
    let newestText = '';
    for (const run of targetRuns) {
      const at = getString(run, ['started_at'], '') || getString(run, ['created_at'], '');
      const ms = Date.parse(at);
      if (Number.isFinite(ms) && ms > newest) { newest = ms; newestText = at; }
    }
    return newestText;
  })();
  const proveOwnershipFirst = canStartBoundedRun && !ownershipDone && !scanActive && !activeStandalone;

  function renderHeader() {
    const hasTarget = Boolean(target);
    const title = hasTarget ? targetDisplayValue(target) : entityId;
    return (
      <header className="page-head td-page-head">
        <div className="td-identity">
          <DetailBackLink route="target-detail" />
          <div className="td-title-cluster">
            <h1 className="page-title mono">{title || 'Target'}</h1>
            {hasTarget ? (
              <div className="td-title-badges">
                <Badge tone={targetEligible ? 'success' : 'warn'} title={`Reported eligibility ${eligibility}; ownership ${verificationState}`}>
                  {targetEligible ? 'Validation unlocked' : 'Ownership pending · checks locked'}
                </Badge>
                <Badge tone="muted">{formatLabel(kind)}</Badge>
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
                <span>Expected: {formatLabel(getString(target, ['expected_behavior', 'expected'], 'Not reported'))}</span>
                <span className="dot" aria-hidden="true">·</span>
                <span className="td-last-check">{lastCheckAt ? <>Last check <time dateTime={lastCheckAt}>{formatDate(lastCheckAt)}</time></> : 'No checks recorded yet'}</span>
              </div>
              <TagEditor tags={tags} canEdit={canWrite} onChange={saveTags} />
            </div>
          ) : null}
        </div>
        {hasTarget ? (
          <div className="td-head-actions">
            {proveOwnershipFirst ? (
              <Button onClick={proveOwnership}>
                <ShieldCheck size={15} aria-hidden="true" />Prove ownership
              </Button>
            ) : null}
            {canStartBoundedRun ? (
              <Button variant={proveOwnershipFirst ? 'secondary' : 'default'} onClick={() => { setTab('validate'); window.requestAnimationFrame(() => document.getElementById(scanActive || activeStandalone ? 'probe-activity-title' : 'td-all-checks')?.scrollIntoView({ behavior: prefersReducedMotion() ? 'auto' : 'smooth', block: 'start' })); }}>
                <Play size={15} aria-hidden="true" />{scanActive || activeStandalone ? 'View activity' : 'Plan validation'}
              </Button>
            ) : null}
            {canStartBoundedRun && (scanActive || activeStandalone) ? (
              <Button variant="danger" onClick={() => scanActive ? setStopOpen(true) : setStopSingleRun({ id: getString(activeStandalone, ['id'], ''), name: displayCheckName(getString(activeStandalone, ['check_id'], '')) })}>
                <Square size={14} aria-hidden="true" />{scanActive ? 'Stop scan' : 'Stop current check'}
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

  const openFindings = deduplicatedOpenFindings
    .map((item) => item.representative)
    .sort((left, right) => (SEVERITY_RANK[getString(right, ['severity'], '').toLowerCase()] ?? 0) - (SEVERITY_RANK[getString(left, ['severity'], '').toLowerCase()] ?? 0));
  const openDetectionCount = deduplicatedOpenFindings.reduce((total, item) => total + item.detectionCount, 0);
  const topFinding = openFindings[0] ?? null;
  const acceptedRiskCount = deduplicatedFindings.filter((item) => ['accepted_risk', 'accepted'].includes(findingStatus(item.representative))).length;
  const fixVerifiedCount = deduplicatedFindings.filter((item) => findingStatus(item.representative) === 'fix_verified').length;
  const recordedResults = (rowCounts.passed ?? 0) + (rowCounts.failed ?? 0) + (rowCounts.inconclusive ?? 0) + (rowCounts.observed ?? 0) + (rowCounts.retained ?? 0);
  const coverage = detail.coverage ?? null;
  const coveragePairs = Array.isArray(coverage?.pairs) ? (coverage!.pairs as DataItem[]).filter((pair) => pair && typeof pair === 'object') : [];
  const retainedPairs = retainedCoveragePairs(coveragePairs);
  const liveNotes: Record<string, string> = Object.fromEntries(retainedPairs.map((pair) => [
    getString(pair, ['check_id'], ''),
    (PAIR_REASON_LABELS[getString(pair, ['pair_reason'], '')] ?? formatLabel(getString(pair, ['pair_reason'], 'not_recorded'))).toLowerCase(),
  ]));
  const efficacy = assessEdgeEfficacy({ rows: selectableRows, edge: edgeDetection, coverage, nowMs: clock });
  const wafRules = wafRuleEnforcement(selectableRows, { coverage, nowMs: clock });
  const canaryMembers = customCanaryMembers(coverage, { checks: checkRows });
  const dimensions = Array.isArray(detail.protection_profile?.dimensions)
    ? (detail.protection_profile!.dimensions as DataItem[]).filter((row) => row && typeof row === 'object')
    : [];

  function renderNextAction(): ReactNode {
    if (!ownershipDone) {
      return (
        <section className="td-next" data-kind="ownership" aria-labelledby="td-next-title">
          <div className="td-next-head">
            <h2 id="td-next-title" tabIndex={-1}>Prove ownership to unlock validation</h2>
            <Badge tone={ownershipStep.tone}>{ownershipStep.label}</Badge>
            <Badge tone="muted">Next step</Badge>
          </div>
          {renderOwnershipPanel()}
        </section>
      );
    }
    if (topFinding) {
      const id = getString(topFinding, ['id'], '');
      const hasEvidence = Array.isArray(topFinding.evidence_ids) && (topFinding.evidence_ids as unknown[]).some((value) => typeof value === 'string' && value.trim());
      return (
        <section className="td-next" data-kind="finding" aria-labelledby="td-next-title">
          <div className="td-next-head">
            <h2 id="td-next-title">{plainFindingTitle(topFinding, [target], checks)}</h2>
            <Badge tone={severityTone(getString(topFinding, ['severity'], ''))}>{formatSeverityLabel(getString(topFinding, ['severity'], 'unknown'))}</Badge>
            <Badge tone="muted">Highest-priority open finding</Badge>
            {hasEvidence ? <Badge tone="muted">Evidence attached</Badge> : <Badge tone="warn">No evidence recorded</Badge>}
          </div>
          <p className="td-copy">
            Opened {formatDate(topFinding.created_at ?? topFinding.opened_at)}
            {openFindings.length > 1 ? `. ${openFindings.length - 1} more open on this target.` : '.'}
            {' '}A later passing check does not close it; {hasEvidence ? 'review the original evidence first.' : 'no supporting evidence is recorded for it yet; open the full finding to review its run.'}
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
            <h2 id="td-next-title">No recorded check results yet</h2>
            <Badge tone="muted">Next step</Badge>
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
          <h2 id="td-next-title">No open findings on this target</h2>
          <Badge tone="muted">Latest recorded results</Badge>
        </div>
        <p className="td-copy">
          Passed checks show behavior in their recorded scenario only. {countLabel(rowCounts.not_run ?? 0, 'compatible check')} {pluralize(rowCounts.not_run ?? 0, 'has', 'have')} no result yet.
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
      const conclusive = Number(coverage.conclusive_count);
      const observationOnly = Number(coverage.observation_only_count);
      const planTitle = `Server applicability plan ${getString(coverage, ['plan_version'], 'version not recorded')}`;
      const countText = (value: unknown) => (value === null || value === undefined || value === '' || !Number.isFinite(Number(value)) ? 'Not recorded' : String(value));
      const cell = (label: string, key: string) => (
        <div key={key}><dt>{label}</dt><dd className="tabular-nums">{countText(coverage[key])}</dd></div>
      );
      return (
        <section className="td-coverage" aria-labelledby="td-coverage-title">
          <header className="td-section-head">
            <div>
              <h2 id="td-coverage-title">Check coverage</h2>
              <p className="td-coverage-scope tabular-nums">
                Catalog {fullCatalog ? fullCatalog.length : 'not loaded'} · Runnable on this target {runAll.length} · Scored for readiness {countText(coverage.applicable_count)}
              </p>
            </div>
          </header>
          <p className="td-copy td-coverage-summary" title={planTitle}>
            {applicable > 0
              ? `${Number.isFinite(conclusive) ? conclusive : 0} of ${applicable} readiness-scored checks have a conclusive result.`
              : 'No readiness-scored checks for this target.'}
          </p>
          <dl className="td-count-grid">
            {cell('Scored for readiness', 'applicable_count')}
            {cell('Evaluated', 'evaluated_count')}
            {cell('Conclusive', 'conclusive_count')}
            {cell('Inconclusive', 'inconclusive_count')}
            {cell('Not run', 'not_run_count')}
            {cell('Stale', 'stale_count')}
            {cell('Unknown', 'unknown_count')}
            {cell('Partial', 'partial_count')}
          </dl>
          {observationOnly > 0 ? (
            <p className="td-copy">{String(observationOnly)} runnable checks are observations only; they run under Validate but are not scored for readiness.</p>
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
                <thead><tr><th scope="col">Dimension</th><th scope="col">Coverage state</th><th scope="col">Evaluated</th><th scope="col">Conclusive</th><th scope="col">Not run</th><th scope="col">Unknown or partial</th><th scope="col">Stale</th></tr></thead>
                <tbody>
                  {dimensions.map((dimension) => {
                    const applicableCount = Number(dimension.applicable_count);
                    const dimensionId = getString(dimension, ['id'], '');
                    const notAssessableReason = getString(dimension, ['not_assessable_reason', 'reason'], '') || DIMENSION_NOT_ASSESSABLE[dimensionId] || DIMENSION_NOT_ASSESSABLE.other;
                    return (
                      <tr key={dimensionId}>
                        <th scope="row">{DIMENSION_LABELS[dimensionId] ?? formatLabel(dimensionId)}</th>
                        <td>{applicableCount > 0 ? formatLabel(getString(dimension, ['status'], 'not_recorded')) : <span className="td-not-assessable"><strong>Not assessable</strong><small>{notAssessableReason}</small></span>}</td>
                        <td className="tabular-nums">{applicableCount > 0 ? `${dimension.evaluated_count ?? 0} of ${applicableCount}` : 'None scored'}</td>
                        <td className="tabular-nums">{String(dimension.conclusive_count ?? 'Not recorded')}</td>
                        <td className="tabular-nums">{String(dimension.not_run_count ?? 'Not recorded')}</td>
                        <td className="tabular-nums">{dimension.unknown_count === undefined && dimension.partial_count === undefined ? 'Not recorded' : `${dimension.unknown_count ?? 0} / ${dimension.partial_count ?? 0}`}</td>
                        <td className="tabular-nums">{String(dimension.stale_count ?? 'Not recorded')}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          ) : null}
          <details className="td-coverage-about">
            <summary>About these numbers</summary>
            <p className="td-copy">
              Catalog counts every check AstraNull offers. Runnable checks fit this target and can be started under Validate. Readiness-scored checks are the runnable checks that can produce a verdict; observation checks run but are never scored.
            </p>
            <p className="td-copy">
              Excluded: <span className="tabular-nums">{countText(coverage.excluded_count)}</span> catalog checks do not fit this target kind, so they are neither run nor scored here.
            </p>
            {dimensions.some((dimension) => dimension.excluded_count !== undefined && dimension.excluded_count !== null) ? (
              <ul className="td-coverage-excluded">
                {dimensions.map((dimension) => (
                  <li key={getString(dimension, ['id'], '')}>
                    {DIMENSION_LABELS[getString(dimension, ['id'], '')] ?? formatLabel(getString(dimension, ['id'], ''))}: <span className="tabular-nums">{String(dimension.excluded_count ?? 'Not recorded')}</span> excluded
                  </li>
                ))}
              </ul>
            ) : null}
            <p className="td-muted" title={planTitle}>Counts come from the server applicability plan.</p>
          </details>
          <p className="td-muted">Coverage shows which readiness-scored checks have results, not whether they passed. Launch gates are re-evaluated by the server when you start a check.</p>
        </section>
      );
    }
    return (
      <section className="td-coverage" aria-labelledby="td-coverage-title">
        <header className="td-section-head">
          <div>
            <h2 id="td-coverage-title">Recorded check results</h2>
            <p>Counts over {selectableRows.length} catalog checks compatible with this target kind. The server applicability plan is not reported yet, so no coverage percentage is shown.</p>
          </div>
        </header>
        <dl className="td-count-grid">
          <div><dt>Gap found</dt><dd className="tabular-nums">{rowCounts.failed ?? 0}</dd></div>
          <div><dt>Protected</dt><dd className="tabular-nums">{rowCounts.passed ?? 0}</dd></div>
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
    if (edgePhase === 'waiting') return 'Another run holds the execution slot for this target. Your detection request starts when it frees up.';
    if (edgePhase === 'error') return edgeError || 'WAF/CDN detection could not be queued.';
    if (edgePhase === 'no_result') return edgeDetectionReasonExplanation(edgeReason) || 'The last detection run finished without a trusted result, so nothing is asserted.';
    if (edgePhase === 'not_started') return DNS_TXT_KINDS.has(kind) ? null : 'No WAF/CDN detection is recorded for this target yet.';
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
      const notTested = requiredInputMissing(item);
      if (notTested) return <NotTestedBadge info={notTested} />;
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
      render: (item) => {
        const state = (item.state || 'open').toLowerCase();
        if (state === 'fix_verified') {
          const basis = fixVerifiedBasisHint(item.representative);
          const badge = <Badge tone="success" title="A later passing check confirmed the fix">Fix verified</Badge>;
          return basis ? <span className="td-finding-cell-stack">{badge}<small className="td-muted td-basis-hint">{basis}</small></span> : badge;
        }
        if (state === 'accepted_risk' || state === 'accepted') return <Badge tone="muted" title="Shown separately; not counted as open risk">Accepted risk</Badge>;
        return formatLabel(state);
      },
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
    { id: 'controls' as const, label: 'Controls' },
    { id: 'coverage' as const, label: 'Rule coverage' },
    ...(kind === 'fqdn' ? [{ id: 'subdomains' as const, label: 'Subdomains' }] : []),
    { id: 'history' as const, label: 'Changes & history' },
  ];

  const reviewRow = review?.mode === 'single' ? checkRows.find((row) => row.checkId === review.checkId) ?? null : null;
  const selectedBound = reviewRow?.maxRequests ?? null;
  const multiSelected = selectedRunIds.length > 1;
  const startReason = multiSelected
    ? (!targetEligible ? OWNERSHIP_LOCKED_REASON : '')
    : singleDisabledReason;
  const probeSourceRanges = Array.isArray(config.siteConfig?.probe_source_ranges)
    ? (config.siteConfig.probe_source_ranges as unknown[]).filter((value): value is string => typeof value === 'string' && value.trim() !== '')
    : [];
  const impactSentence = (invasive: number, total: number) => (
    <p className="td-review-impact" data-invasive={invasive > 0 || undefined}>
      <strong>Traffic impact:</strong>{' '}
      {invasive === 0
        ? 'All non-invasive. These checks only observe with ordinary requests.'
        : `${invasive} invasive and ${total - invasive} non-invasive. Invasive checks send bounded, attack-shaped traffic and can trigger WAF, IDS or SOC alerts.`}
    </p>
  );
  const trafficNotice = (bound: string) => (
    <>
      Requests come from AstraNull signed public probe workers. Most carry a User-Agent containing “AstraNull”, but some phases deliberately vary or omit headers, so the request bound ({bound}) is the reliable limit. Traffic starts when you confirm and stops at the timeout or when you choose Stop.
      {' '}Source addresses: {probeSourceRanges.length ? <span className="mono">{probeSourceRanges.join(', ')}</span> : 'ask your AstraNull operator'}.
      {' '}<a href="#support" className="td-inline-link">Share with your SOC/WAF team</a>
    </>
  );

  return (
    <div className="content target-detail-view">
      {renderHeader()}
      {['fqdn', 'url'].includes(kind) ? <InitialEdgeStatus key={entityId} targetId={entityId} config={config} session={session} onDispatched={reload} /> : null}
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
        {tab === 'controls' && target ? (
          <ControlDeclarations
            config={config}
            session={session}
            target={target}
            canWrite={canWrite}
            declarations={declarationsDoc}
            loadState={declarationsLoad.scope === executionScope ? declarationsLoad.status : 'loading'}
            loadError={declarationsLoad.error}
            perspectives={perspectives}
            perspectivesError={perspectivesError}
            focusSection={getRouteParam('section')}
            originRelations={originRelations}
            originRelationsHref={`#target-detail?${new URLSearchParams({ id: entityId, tab: 'overview', section: 'origin-relations' }).toString()}`}
            onReload={() => setControlsReload((value) => value + 1)}
            onSaved={(next) => {
              setDeclarationsLoad({ scope: executionScope, status: 'ready', doc: next, error: '' });
              setCoverageReload((value) => value + 1);
              setBanner('Control declarations saved and recorded in the audit log.');
            }}
            onLatest={(latest) => {
              setDeclarationsLoad({ scope: executionScope, status: 'ready', doc: latest, error: '' });
              setCoverageReload((value) => value + 1);
            }}
            onDirtyChange={onControlsDirty}
          />
        ) : null}
        {tab === 'coverage' && target ? (
          <div className="td-rule-coverage">
            <RuleCoveragePanel config={config} session={session} targetId={entityId} canWrite={canWrite} reloadKey={coverageReload} />
          </div>
        ) : null}
        {tab === 'subdomains' && target ? (
          <TargetSubdomains key={entityId} target={target} config={config} session={session} canWrite={canWrite} canStart={canStartBoundedRun} />
        ) : null}
        {tab === 'overview' ? (
          <div className="td-overview">
            {renderNextAction()}
            <ProviderObservations
              rows={providerRows}
              effectiveness={effectiveness}
              evaluating={edgeEvaluating}
              note={edgeNote()}
              action={detectAction}
              onInspect={inspectProvider}
              efficacy={efficacy}
              wafRules={wafRules}
              canaryMembers={canaryMembers}
              checkName={displayCheckName}
              onOpenChecks={() => setTab('validate')}
            />
            {renderCoverage()}
            {target?.kind === 'fqdn' ? <OriginExposure key={`${entityId}:${sessionIdentity(session)}`} config={config} session={session} target={target} canWrite={canWrite} enabled={deploymentFeatures?.origin_clues === true} /> : null}
            {target ? <TargetAuthorization target={target} config={config} session={session} canWrite={canWrite} ownershipDone={ownershipDone} /> : null}
            {target ? (
              <OriginRelations
                config={config}
                session={session}
                target={target}
                profile={(detail?.protection_profile as DataItem | undefined) ?? null}
                canWrite={canWrite}
                canStart={canStartBoundedRun}
                ownershipDone={ownershipDone}
                onStarted={onReviewedExecutionStarted}
                onChanged={() => { void reload(); }}
              />
            ) : null}
            {target && !protectionValidationEnabled ? (
              <p className="td-muted small" role="status" data-testid="protection-validation-disabled">
                Declared entry paths and entry-path comparisons are not enabled for this workspace. Nothing is checked until an administrator enables them.
              </p>
            ) : null}
            {target && protectionValidationEnabled ? (
              <DeclaredEntryPaths
                config={config}
                session={session}
                target={target}
                canWrite={canWrite}
                canStart={canStartBoundedRun}
                ownershipDone={ownershipDone}
                onStarted={onReviewedExecutionStarted}
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
                The linked check <span className="mono">{selectedCheckId}</span> is not in the loaded catalog. No other check was selected.
              </div>
            ) : null}
            {showActivity ? (
              <ProbeActivity
                config={config} session={session} runId={activityRunId}
                checkName={activityCheckName}
                running={activityRunning} canStop={canStartBoundedRun && Boolean(activityRunId) && !inspectingActivityRun}
                onStop={() => setStopSingleRun({ id: activityRunId, name: activityCheckName || 'Current check' })}
                onFollowActive={selectedRow && activeCheckRow && selectedRow.checkId !== activeCheckRow.checkId ? () => selectCheck(activeCheckRow.checkId) : undefined}
                notSent={activityRow && !activityRunId && ['blocked', 'skipped', 'cancelled'].includes(activityRow.status) ? { reason: activityRow.reason, at: activityRow.finishedAt || activityRow.startedAt } : null}
              />
            ) : null}
            <CheckQueue
              rows={checkRows}
              runnableCheckIds={runnableIds}
              runAllCount={runAll.length}
              catalogCount={fullCatalog?.length}
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
              onActivity={(row) => { selectCheck(row.checkId); window.requestAnimationFrame(() => document.getElementById('probe-activity-title')?.scrollIntoView({ behavior: prefersReducedMotion() ? 'auto' : 'smooth', block: 'start' })); }}
              runAllDisabledReason={runAllDisabledReason}
              runAllBlockedReason={runAllBlockedReason}
              recommendedRow={activeStandalone ? null : recommendedRow}
              onStartRecommended={(row) => { setRunSelection([]); selectCheck(row.checkId); setReview({ mode: 'single', checkId: row.checkId }); }}
              runSelection={selectedRunIds}
              onRunSelectionChange={setRunSelection}
              liveNotes={liveNotes}
              prerequisites={prerequisites}
              targetId={entityId}
              footer={<>
                {catalogError ? <div role="alert"><p>{catalogError} Only the loaded selection subset is shown.</p><Button size="sm" variant="secondary" onClick={() => setCatalogReload((value) => value + 1)}>Retry catalog</Button></div> : fullCatalog === null ? <p role="status">Loading the full check catalog. Only the loaded selection subset is shown.</p> : null}
                {remainingCatalog.length ? <details className="td-retained td-catalog-requirements">
                  <summary>{remainingCatalog.length} catalog checks not runnable on this target · requirements</summary>
                  <p>These definitions are included in the full catalog above. Required setup never counts as passed protection.</p>
                  <ul>{remainingCatalog.map((check) => {
                    const prerequisite = targetCheckAvailability(check, target, prerequisiteContext);
                    const section = prerequisiteSection(prerequisite);
                    return <li key={getString(check, ['check_id'], '')}>
                    <span className="td-requirement-row">
                      <strong>{getString(check, ['name'], '')}</strong> <code>{getString(check, ['check_id'], '')}</code>
                      {prerequisite.state !== 'ready' ? <Badge tone={prerequisiteTone(prerequisite)}>{prerequisite.label}</Badge> : null}
                    </span>
                    <p>{targetCheckRequirement(check, target, prerequisiteContext)}</p>
                    {prerequisite.state === 'soc_only' ? <p><a className="td-inline-link" href="#support">Request it through AstraNull SOC</a></p> : null}
                    {section ? <p><a className="td-inline-link" href={controlsHref(entityId, section)}>{prerequisiteCta(prerequisite)}</a></p> : null}
                    {Array.isArray(check.required_customer_setup) && check.required_customer_setup.length ? <p className="td-muted">Required setup: {(check.required_customer_setup as string[]).map((value) => formatLabel(value)).join(', ')}</p> : null}
                  </li>;
                  })}</ul>
                  <Button size="sm" variant="secondary" onClick={() => setTab('overview')}>Declare origin and entry paths</Button>
                </details> : null}
              </>}
              scanActivity={scanActivity}
              selectedRunEvents={selectedRunEvents}
              targetValue={targetDisplayValue(target)}
            />
            {canStartBoundedRun && !scanActive && !activeStandalone ? (
              <div className="td-start-bar" role="region" aria-label="Start the selected check">
                <span className="td-start-copy">
                  {multiSelected
                    ? <><strong>{selectedRunIds.length} checks selected</strong> on <span className="mono">{targetDisplayValue(target)}</span></>
                    : startRow
                      ? <><strong>{startRow.name}</strong> on <span className="mono">{targetDisplayValue(target)}</span>{selectedRunIds.length === 1 ? <span className="td-muted"> · 1 check selected</span> : null}</>
                      : 'No check selected'}
                </span>
                {selectedRunIds.length ? <Button size="sm" variant="ghost" onClick={() => setRunSelection([])}>Clear</Button> : null}
                {!ownershipDone ? <Button size="sm" variant="ghost" onClick={() => focusOwnership('td-validate-ownership')}>Go to ownership step</Button> : null}
                <Button
                  data-focus-key={multiSelected ? 'check-start-selected' : `check-start-${startCheckId}`}
                  disabled={!targetEligible || busy !== '' || scanActive || (!multiSelected && Boolean(singleDisabledReason))}
                  aria-describedby={startReason ? 'td-start-reason' : undefined}
                  onClick={() => setReview(multiSelected ? { mode: 'selected', checkIds: selectedRunIds } : { mode: 'single', checkId: startCheckId })}
                >
                  <Play size={15} aria-hidden="true" />{selectedRunIds.length ? `Review and start ${selectedRunIds.length}` : 'Review and start'}
                </Button>
                {startReason ? <span className="td-muted td-start-reason" id="td-start-reason">{startReason}</span> : null}
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
                  {openFindings.length} open of {deduplicatedFindings.length} unique finding{deduplicatedFindings.length === 1 ? '' : 's'}.
                  {findings.length > deduplicatedFindings.length
                    ? ` ${findings.length} detections recorded${openDetectionCount > openFindings.length ? `, ${openDetectionCount} on open findings` : ''}; repeat detections of the same issue count as one finding.`
                    : ''}{' '}
                  Each opens the full detection history and evidence.
                </p>
                {acceptedRiskCount || fixVerifiedCount ? (
                  <div className="td-findings-split" aria-label="Findings outside open risk">
                    {acceptedRiskCount ? <Badge tone="muted" title="Risk formally accepted; shown separately and not counted as open risk">{`${acceptedRiskCount} accepted risk · not open risk`}</Badge> : null}
                    {fixVerifiedCount ? <Badge tone="success" title="A later passing check with the same scope and check version confirmed the fix">{`${fixVerifiedCount} fix verified`}</Badge> : null}
                  </div>
                ) : null}
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
              checkName={(checkId) => checkPresentation(checks.find((check) => getString(check, ['check_id', 'id'], '') === checkId) ?? checkId).name}
              onInspectRun={(runId, checkId, focusKey) => openInspector({ entry: 'check_result', target_id: entityId, check_id: checkId, test_run_id: runId }, focusKey)}
            />
            {target && protectionValidationEnabled ? (
              <FirewallChangeComparison
                config={config}
                session={session}
                target={target}
                canWrite={canWrite}
                canStart={canStartBoundedRun}
                ownershipDone={ownershipDone}
                onStarted={onReviewedExecutionStarted}
              />
            ) : null}
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

      {tab === 'overview' ? (
        <section className="td-facts" aria-labelledby="td-facts-title">
          <header className="td-section-head"><div><h2 id="td-facts-title">Target facts</h2></div></header>
          <div className="table-wrap" tabIndex={0} role="region" aria-label="Target facts, scrollable">
            <table className="data-table">
              <tbody>
                <tr><th scope="row">Target ID</th><td><span className="mono">{entityId}</span></td></tr>
                <tr><th scope="row">Declared value</th><td><span className="mono">{targetDisplayValue(target)}</span></td></tr>
                <tr><th scope="row">Kind</th><td>{formatLabel(kind)}</td></tr>
                <tr><th scope="row">Declaration source</th><td>{plainCheckName(targetDeclarationProvenanceLabel(target))}</td></tr>
                <tr><th scope="row">Ownership method</th><td><span className="mono">{ownershipMethodText(verification)}</span></td></tr>
                {detail.loa ? <tr><th scope="row">Authorization</th><td>{formatLabel(getString(detail.loa, ['state'], 'Not reported'))}</td></tr> : null}
              </tbody>
            </table>
          </div>
        </section>
      ) : null}

      <ConfirmModal
        open={review !== null}
        title={review?.mode === 'detect'
          ? `Detect WAF and CDN on ${targetDisplayValue(target)}?`
          : review?.mode === 'all'
            ? `Start ${runAll.length} checks on ${targetDisplayValue(target)}?`
            : review?.mode === 'selected'
              ? `Start ${reviewSelectedRows.length} selected checks on ${targetDisplayValue(target)}?`
              : `Start ${reviewRow?.name ?? 'this check'} on ${targetDisplayValue(target)}?`}
        description={(
          <div className="stack-tight scan-review">
            {review?.mode === 'detect' ? (
              <>
                <p>One bounded fingerprint run against this exact target: DNS resolution plus benign HTTP requests from the signed worker.</p>
                <p>Upper bound: {detectBound !== null ? `${detectBound} requests` : 'not recorded in the catalog'}. Ownership: {ownershipDone ? 'verified' : 'not verified'}.</p>
                <p>It identifies providers only. It does not test blocking or capacity.</p>
                <p className="td-review-traffic"><strong>What your team will see:</strong> {trafficNotice(detectBound !== null ? `at most ${detectBound} requests` : 'shown above')}</p>
              </>
            ) : review?.mode === 'all' || review?.mode === 'selected' ? (
              <>
                {review.mode === 'all' ? (
                  <>
                    <p><strong>{runAll.length} bounded external checks</strong> across {runAllCategoryCount} categories, at most {runAllRequestBound} probe requests in total.</p>
                    <p>Runs every eligible check for this target, including provider, DNS, transport, and protocol observations. These observations do not score as readiness verdicts.</p>
                    {assessmentExcludedRows.length ? (
                      <details className="td-requirements">
                        <summary>{assessmentExcludedRows.length} of {inventoryChecks.length} definitions cannot run in this evaluation</summary>
                        <p>These are not executed and receive no new result or readiness credit. Resolve setup requirements or use the authorized workflow where available.</p>
                        <ul>{assessmentExcludedRows.map((row) => <li key={row.checkId}><strong>{row.name}</strong>: {prerequisites[row.checkId]?.detail || 'Unavailable in this evaluation.'}</li>)}</ul>
                      </details>
                    ) : null}
                    {impactSentence(runAll.filter((check) => classifyCheckImpact(check).id === 'invasive').length, runAll.length)}
                  </>
                ) : (
                  <>
                    <p><strong>{reviewSelectedRows.length} bounded external checks</strong> across {selectedCategoryCount} {selectedCategoryCount === 1 ? 'category' : 'categories'}, at most {selectedRequestBound} probe requests in total.{selectedUnbounded ? ` ${selectedUnbounded} of them ${selectedUnbounded === 1 ? 'has' : 'have'} no request bound recorded in the catalog.` : ''}</p>
                    {selectedObservationCount ? <p>{selectedObservationCount} of these {selectedObservationCount === 1 ? 'has' : 'have'} no readiness credit. Scoped policy verdicts remain separate from readiness conclusions.</p> : null}
                    {impactSentence(selectedInvasiveCount, reviewSelectedRows.length)}
                  </>
                )}
                <p>They run one at a time inside your safe-run limits; if an hourly limit is reached the scan pauses and shows when it resumes. While it runs it holds this target&apos;s execution slot, so no other check can start on this target until it finishes. You can stop it at any time.</p>
                <p>The server re-checks ownership, safe windows, rate and concurrency gates when you start.</p>
                <p className="td-review-traffic"><strong>What your team will see:</strong> {trafficNotice(`at most ${review.mode === 'all' ? runAllRequestBound : selectedRequestBound} requests`)}</p>
                {!ownershipDone ? <p className="td-form-error" role="alert">{OWNERSHIP_LOCKED_REASON}</p> : reviewSlotReason ? <p className="td-form-error" role="alert">{reviewSlotReason}</p> : null}
              </>
            ) : (
              <>
                <dl className="td-review-list">
                  <div><dt>Target</dt><dd className="mono">{targetDisplayValue(target)}</dd></div>
                  <div><dt>Check</dt><dd>{reviewRow?.name ?? 'Not selected'} <span className="mono">{review?.mode === 'single' ? review.checkId : ''}</span></dd></div>
                  <div><dt>Upper bound</dt><dd>{selectedBound !== null ? `${selectedBound} request${selectedBound === 1 ? '' : 's'}` : 'Not recorded in the catalog'}{reviewRow?.timeoutMs ? `, ${reviewRow.timeoutMs} ms timeout` : ''}</dd></div>
                  {reviewRow ? <div><dt>Traffic impact</dt><dd>{CHECK_IMPACT_CLASSES[rowImpact(reviewRow)].label}. {CHECK_IMPACT_CLASSES[rowImpact(reviewRow)].summary}</dd></div> : null}
                  <div><dt>Result type</dt><dd>{reviewRow?.producesVerdict ? reviewRow.readinessCapable ? 'Produces a readiness verdict' : 'Scoped verdict; no readiness credit' : 'Observation only; no readiness credit'}</dd></div>
                  <div><dt>Ownership</dt><dd>{ownershipDone ? 'Verified' : 'Not verified'}</dd></div>
                  <div><dt>What your team will see</dt><dd>{trafficNotice(selectedBound !== null ? `at most ${selectedBound} request${selectedBound === 1 ? '' : 's'}` : 'not recorded in the catalog')}</dd></div>
                </dl>
                <p>The server re-checks ownership, safe windows, rate and concurrency gates when you start. A bounded check does not measure volumetric capacity.</p>
                {!ownershipDone ? <p className="td-form-error" role="alert">{OWNERSHIP_LOCKED_REASON}</p> : reviewSlotReason ? <p className="td-form-error" role="alert">{reviewSlotReason}</p> : null}
              </>
            )}
          </div>
        )}
        confirmLabel={review?.mode === 'detect' ? 'Start detection' : review?.mode === 'all' ? 'Start all checks' : review?.mode === 'selected' ? `Start ${reviewSelectedRows.length} checks` : 'Start check'}
        confirmTone="default"
        confirmDisabled={review !== null && review.mode !== 'detect' && (!ownershipDone || Boolean(reviewSlotReason) || (review.mode === 'all' && Boolean(runAllBlockedReason)))}
        busy={busy === 'run' || busy === 'run-all'}
        onCancel={() => setReview(null)}
        onConfirm={() => void startReviewed()}
      />
      <ConfirmModal
        open={stopSingleRun !== null}
        title={`Stop ${stopSingleRun?.name || 'this check'}?`}
        description={scanActive ? 'This stops only this check. The remaining checks in this scan continue. Use Stop scan to stop the whole scan.' : 'The worker stops further attempts and retains recorded activity. A bounded request already in flight may finish.'}
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
          setBanner('Scan stop requested. Queued checks cannot start; finished results are kept. Worker acknowledgment remains separate.');
          void loadTargetActivity();
        }}
      />
    </div>
  );
}
