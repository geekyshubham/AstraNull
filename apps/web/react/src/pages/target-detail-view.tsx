import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import {
  Activity,
  Check,
  CircleCheck,
  CircleDashed,
  Clock,
  Cloud,
  Copy,
  FileCheck2,
  Network,
  Play,
  Plus,
  RefreshCw,
  Server,
  ShieldCheck,
  Target,
  TriangleAlert,
  X,
} from 'lucide-react';
import {
  issueOwnershipChallenge,
  patchTargetTags,
  populateTargetDetail,
  verifyOwnershipChallenge,
  type OwnershipChallenge,
  type TargetDetailPayload,
} from '../lib/target-detail-api';
import { hasEvidenceBackedVerdict, publishedRunVerdict } from '../lib/run-verdict';
import { findingStatus, isFindingOpen } from '../lib/finding-lifecycle.mjs';
// @ts-ignore Plain ESM keeps truthfulness rules executable in focused node tests.
import { addTargetTag, apiErrorCode, edgeDetectionReasonExplanation, isTargetRunEligible, ownershipMethodLabel, ownershipStepStatus, removeTargetTag, targetDeclarationProvenanceLabel, targetDisplayValue, uniqueAppliedChecks, uniqueRecentRuns, uniqueVerificationHistory } from '../lib/target-detail.mjs';
import { VerifyChip, resolveTargetVerificationProvenance } from '../lib/verify-chip';
import { buildDetailHref } from '../lib/route-params';
import type { DataItem, PortalConfig, Session } from '../lib/types';
import { formatDate, formatSeverityLabel } from '../lib/utils';
import { AnchorButton, Button } from '../components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../components/ui/card';
import { EvidenceGuide } from '../components/ui/evidence-guide';
import { emptyStateFromApi } from '../lib/empty-from-api';
import { DataTable, type TableColumn } from '../components/ui/table';
import { Badge, type BadgeProps } from '../components/ui/badge';
import { Tabs } from '../components/ui/tabs';
import { DesignVariantSwitch, useDesignVariant } from '../components/ui/design-variant';
import { canStartRun } from '../lib/run-permissions.mjs';
import { requestJson } from '../lib/api';
import { prefersReducedMotion } from '../lib/motion';
import { apiErrorMessage } from '../lib/error-messages';
import { ConfirmModal } from '../lib/crud-ui';
import { isScanActive, nextPollDelay, scanErrorMessage } from '../lib/validation-scan.mjs';
import {
  EDGE_DETECTION_CHECK_ID,
  assessEdgeEfficacy,
  buildCheckRows,
  declarationOnlyChecks,
  edgeDetectionPhase,
  runAllChecks,
  shouldAutoDetectEdge,
  validationScansPathForTarget,
} from '../lib/domain-checks.mjs';
import { AllChecksPanel, EdgeProtectionCard } from '../components/targets/domain-protection';
import { CancelScanDialog } from '../components/runs/validation-scans-table';
// @ts-ignore Plain ESM keeps evidence-conservative labels directly testable with node:test.
import { evidenceModePresentation, plainCheckName, plainCodeLabel, plainFindingTitle, plainProtectionLabel, plainVerdictDescription, plainVerdictLabel, plainVerificationLabel } from '../lib/plain-language.mjs';
import './target-detail-view.css';

type StatTone = NonNullable<BadgeProps['tone']>;
type WorkspaceTab = 'protection' | 'edge' | 'runs' | 'findings';
type EdgeLocalState = '' | 'pending' | 'blocked' | 'error';

const TARGET_RUNS_LIMIT = 500;
const EDGE_POLL_MS = 4_000;
const EDGE_POLL_MAX_MS = 3 * 60 * 1000;
const EDGE_BLOCKED_RETRY_MS = 15_000;
const EDGE_BLOCKED_MAX_RETRIES = 20;
const DNS_AUTO_RECHECK_MS = 30_000;
const DNS_AUTO_RECHECK_MAX_MS = 15 * 60 * 1000;
const ACTIVE_STEP_STATUSES = new Set(['pending', 'deferred', 'starting', 'running', 'collecting']);

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

function formatLabel(value: string, fallback = 'Not reported') {
  const trimmed = value.trim();
  if (!trimmed) return fallback;
  const friendly: Record<string, string> = {
    fqdn: 'Domain name',
    ip: 'IP address',
    cidr: 'CIDR range',
    hostname: 'Hostname',
    cloud_baseline: 'Protected path baseline',
    must_block_before_origin: 'Block before the origin server',
  };
  const key = trimmed.toLowerCase();
  if (friendly[key]) return friendly[key];
  const label = trimmed.replace(/_/g, ' ');
  return label.charAt(0).toUpperCase() + label.slice(1);
}

function verificationTone(state: string): StatTone {
  const key = state.trim().toLowerCase();
  if (['dns_verified', 'provider_verified', 'user_confirmed', 'verified'].includes(key)) return 'success';
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

function protectionStateTone(value: string): StatTone {
  const key = value.trim().toLowerCase();
  if (['protected', 'pass', 'passed', 'detected', 'not_exposed', 'active'].includes(key)) return 'success';
  if (['underprotected', 'unprotected', 'fail', 'failed', 'exposed', 'bypassable', 'penetrated', 'error'].includes(key)) return 'danger';
  if (['edge_protected', 'inconclusive', 'suspected', 'pending', 'degraded'].includes(key)) return 'warn';
  return 'muted';
}

function edgeStatusTone(status: string): StatTone {
  const key = status.trim().toLowerCase();
  if (key === 'detected') return 'success';
  if (key === 'error') return 'danger';
  if (key === 'inconclusive') return 'warn';
  if (key === 'pending') return 'info';
  return 'muted';
}

/**
 * ADR-0008: agents are gone and verdicts are external-probe only. Legacy records may still carry
 * `agent_verified` / `agent_observation`. The server ranks that proof unverified, so the UI asks for
 * re-verification instead of showing it as verified or using "observed from inside" language.
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

function DetailEntityLink({ route, id, label }: { route: 'target-group-detail' | 'finding-detail' | 'run-detail' | 'target-detail'; id: string; label?: string }) {
  if (!id) return <span className="muted">None</span>;
  return (
    <AnchorButton size="sm" variant="ghost" href={buildDetailHref(route, id)} onClick={(event) => event.stopPropagation()}>
      {label ?? id}
    </AnchorButton>
  );
}

function EvidenceModeCell({ item, check }: { item: DataItem; check?: DataItem | null }) {
  const mode = evidenceModePresentation(item, check);
  return (
    <span className="evidence-mode-cell">
      <Badge tone={mode.tone} title={`${mode.detail}${mode.code ? ` Technical tier ${mode.code}.` : ''}`}>
        {mode.label}{mode.code ? ` · ${mode.code}` : ''}
      </Badge>
    </span>
  );
}

/** One clipboard-copy control with a transient confirmation, keyboard-operable, no color-only cue. */
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

/** The tag editor: read-only chips when the role cannot write, editable chips + add form otherwise. */
function TagEditor({
  tags,
  canEdit,
  onChange,
}: {
  tags: string[];
  canEdit: boolean;
  onChange: (next: string[]) => Promise<void>;
}) {
  const [draft, setDraft] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  async function commit(next: string[]) {
    setBusy(true);
    try {
      await onChange(next);
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
    <>
      <div className="td-tags">
        {tags.length === 0 ? <span className="td-tag-empty">No tags yet</span> : null}
        {tags.map((tag) => (
          <span key={tag} className="td-tag badge-identifier">
            {tag}
            {canEdit ? (
              <button
                type="button"
                aria-label={`Remove tag ${tag}`}
                disabled={busy}
                onClick={() => void commit(removeTargetTag(tags, tag) as string[])}
              >
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
          {error ? <span className="td-tag-error" role="alert">{error}</span> : null}
        </div>
      ) : null}
    </>
  );
}

type SummaryItem = { id: string; label: string; value: string; tone?: StatTone; note?: string; numeric?: boolean };

/** Plain-language WAF/CDN detection phase. Detection state only, never an effectiveness claim. */
function edgeSummaryLabel(phase: string, available: boolean): { label: string; tone: StatTone } {
  if (!available) return { label: 'Not enabled', tone: 'muted' };
  const map: Record<string, { label: string; tone: StatTone }> = {
    detected: { label: 'Edge detected', tone: 'success' },
    not_detected: { label: 'No edge detected', tone: 'warn' },
    inconclusive: { label: 'Not enough evidence', tone: 'warn' },
    error: { label: 'Detection failed', tone: 'danger' },
    evaluating: { label: 'Evaluating', tone: 'info' },
    pending: { label: 'Evaluating', tone: 'info' },
    locked: { label: 'Waiting for ownership', tone: 'muted' },
    waiting: { label: 'Queued', tone: 'muted' },
    no_result: { label: 'No usable result', tone: 'warn' },
    not_started: { label: 'Not started', tone: 'muted' },
  };
  return map[phase] ?? { label: 'Not enough evidence', tone: 'warn' };
}

function SummaryToneIcon({ tone }: { tone?: StatTone }) {
  if (!tone || tone === 'default') return null;
  const Icon = tone === 'success' ? CircleCheck : tone === 'info' ? Clock : tone === 'muted' ? CircleDashed : TriangleAlert;
  return <Icon size={16} className="td-summary-icon" data-tone={tone} aria-hidden="true" />;
}

/** Premium-only at-a-glance strip. Every value is derived from the same payload the sections below render. */
function SummaryStrip({ items }: { items: SummaryItem[] }) {
  return (
    <section className="td-summary-region" aria-label="Target summary">
    <dl className="td-summary">
      {items.map((item) => (
        <div key={item.id} className="td-summary-item">
          <dt>{item.label}</dt>
          <dd className={item.numeric ? 'td-summary-value tabular-nums' : 'td-summary-value'}>
            <SummaryToneIcon tone={item.tone} />
            <span>{item.value}</span>
          </dd>
          {item.note ? <dd className="td-summary-note">{item.note}</dd> : null}
        </div>
      ))}
    </dl>
    </section>
  );
}

function buildOwnershipHistory(verification: DataItem | null) {
  const rawHistory = Array.isArray(verification?.history) ? verification.history : [];
  return uniqueVerificationHistory(rawHistory) as DataItem[];
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
  const [startedRunId, setStartedRunId] = useState('');
  const [selectedCheckId, setSelectedCheckId] = useState('');
  const [tab, setTab] = useState<WorkspaceTab>('protection');
  const [scan, setScan] = useState<DataItem | null>(null);
  const [targetRuns, setTargetRuns] = useState<DataItem[]>([]);
  const [edgeLocal, setEdgeLocal] = useState<EdgeLocalState>('');
  const [edgeError, setEdgeError] = useState('');
  const [edgeReason, setEdgeReason] = useState('');
  const [confirmRunAll, setConfirmRunAll] = useState(false);
  const [stopOpen, setStopOpen] = useState(false);
  const edgeAttemptedRef = useRef(new Set<string>());
  const edgeRetriesRef = useRef(0);
  // Presentation only: both variants render the same data, actions, and states.
  const [variant, setVariant] = useDesignVariant('target-detail');

  async function reload() {
    const refreshed = await populateTargetDetail(config, session, entityId);
    setDetail(refreshed);
    return refreshed;
  }

  useEffect(() => {
    let cancelled = false;
    setSelectedCheckId('');
    setDetail((current) => ({
      ...(current ?? {
        target: null, verification: null, waf_posture: null, edge_detection: null,
        checks_applied: [], runs_recent: [], findings: [], loa: null, counts: null,
        tags: [], ownership_challenge: null, loading: true,
      }),
      loading: true,
    }));
    populateTargetDetail(config, session, entityId).then((payload) => { if (!cancelled) setDetail(payload); });
    return () => { cancelled = true; };
  }, [config, session, entityId]);

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
  const targetGroupId = getString(target, ['target_group_id'], '');
  const targetGroupName = getString(
    targetGroups.find((group) => getString(group, ['id'], '') === targetGroupId) ?? null,
    ['name'],
    getString(target, ['target_group_name'], targetGroupId),
  );
  const canWrite = canStartRun(session.role);
  const canStartBoundedRun = canStartRun(session.role);

  const checksApplied = uniqueAppliedChecks(detail?.checks_applied) as DataItem[];
  const checkById = useMemo(
    () => new Map([...checks, ...checksApplied].map((check) => [getString(check, ['check_id', 'id'], ''), check])),
    [checks, checksApplied],
  );
  const displayCheckName = (checkId: string) => plainCheckName(getString(checkById.get(checkId), ['name', 'title', 'check_name'], checkId || 'Unnamed check'));
  const runsRecent = uniqueRecentRuns(detail?.runs_recent) as DataItem[];
  const findings = Array.isArray(detail?.findings) ? detail!.findings : [];
  const ownershipHistory = buildOwnershipHistory(verification);

  const effectiveSelectedCheckId = checksApplied.some((c) => getString(c, ['check_id', 'id'], '') === selectedCheckId)
    ? selectedCheckId
    : '';
  const selectedCheck = checksApplied.find((c) => getString(c, ['check_id', 'id'], '') === effectiveSelectedCheckId) ?? null;

  // Latest evidence-backed verdict across recent runs, for the review step.
  const latestVerdictRun = runsRecent.find((run) => recentRunVerdict(run));
  const latestVerdict = latestVerdictRun ? recentRunVerdict(latestVerdictRun) : '';

  // ---- Run all checks + WAF/CDN edge detection -------------------------------------------------
  const runAll = useMemo(() => (target ? runAllChecks(checks, target) as DataItem[] : []), [checks, target]);
  const declarationOnlyCount = useMemo(() => (target ? declarationOnlyChecks(checks, target).length : 0), [checks, target]);
  const checkRows = useMemo(() => buildCheckRows({ checks: runAll, scan, runs: targetRuns }), [runAll, scan, targetRuns]);
  const edgeDetection = detail?.edge_detection ?? null;
  const edgeRequest = detail?.edge_detection_request ?? null;
  const efficacy = useMemo(() => assessEdgeEfficacy({ rows: checkRows, edge: edgeDetection }), [checkRows, edgeDetection]);
  const scanActive = isScanActive(scan);
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
  const groupIdForRuns = targetGroupId;
  const earlyOwnershipDone = (ownershipStepStatus(verificationState, challenge) as { done: boolean }).done;

  const loadTargetActivity = useCallback(async () => {
    if (!groupIdForRuns) return;
    const [scanList, runList] = await Promise.all([
      requestJson(config, session, validationScansPathForTarget(groupIdForRuns, entityId)).catch(() => null) as Promise<DataItem | null>,
      requestJson(config, session, `/v1/test-runs?target_id=${encodeURIComponent(entityId)}&limit=${TARGET_RUNS_LIMIT}`).catch(() => null) as Promise<DataItem | null>,
    ]);
    if (scanList && Array.isArray(scanList.items)) setScan((scanList.items[0] as DataItem | undefined) ?? null);
    if (runList && Array.isArray(runList.items)) setTargetRuns(runList.items as DataItem[]);
  }, [config, session, entityId, groupIdForRuns]);

  useEffect(() => {
    setScan(null);
    setTargetRuns([]);
    setEdgeLocal('');
    setEdgeError('');
    setEdgeReason('');
    edgeRetriesRef.current = 0;
  }, [entityId]);

  useEffect(() => { void loadTargetActivity(); }, [loadTargetActivity]);

  // Follow an active run-all scan. The fingerprint step persists the edge detection, so refresh
  // the target when it settles; refresh everything when the scan finishes.
  useEffect(() => {
    if (!scanId || !scanActive) return undefined;
    let stopped = false;
    let timer: number | undefined;
    let errors = 0;
    let fingerprintWasActive = fingerprintStepActive;
    const poll = async () => {
      try {
        const next = await requestJson(config, session, `/v1/validation-scans/${encodeURIComponent(scanId)}`) as DataItem;
        if (stopped) return;
        errors = 0;
        setScan(next);
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
    // reload is stable enough for this call site; it only reads the current entity.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [config, session, entityId, targetGroupId, loadTargetActivity]);

  // Onboarding: once ownership is proven, detect the WAF/CDN edge right away (one bounded,
  // signed-worker fingerprint run). Never before ownership: the server would refuse, and the
  // page must not imply it can probe a domain the tenant has not verified.
  useEffect(() => {
    if (!detail || detail.loading || !target) return;
    const attempted = edgeAttemptedRef.current.has(entityId);
    if (!shouldAutoDetectEdge({
      eligible: targetEligible,
      featureEnabled: wafEdgeEnabled,
      canRun: canStartBoundedRun,
      edge: edgeDetection,
      request: edgeRequest,
      scanActive,
      attempted,
      hasPriorRuns: Number(detail.counts?.runs_total ?? runsRecent.length) > 0,
    })) return;
    edgeAttemptedRef.current.add(entityId);
    void queueEdgeDetection();
  }, [detail, target, entityId, targetEligible, wafEdgeEnabled, canStartBoundedRun, edgeDetection, edgeRequest, scanActive, queueEdgeDetection, runsRecent.length]);

  // Another run in the group holds the single concurrency slot: retry until it frees up.
  useEffect(() => {
    if (edgeLocal !== 'blocked' || edgeDetection || scanActive) return undefined;
    if (edgeRetriesRef.current >= EDGE_BLOCKED_MAX_RETRIES) return undefined;
    const timer = window.setTimeout(() => {
      edgeRetriesRef.current += 1;
      void queueEdgeDetection();
    }, EDGE_BLOCKED_RETRY_MS);
    return () => window.clearTimeout(timer);
  }, [edgeLocal, edgeDetection, scanActive, queueEdgeDetection]);

  // While detection is in flight, refresh the target until the signed result is persisted.
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
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [edgeEvaluating, edgeDetection, fingerprintStepActive, loadTargetActivity]);

  // A finished detection run without a persisted result: ask why, so the card can say so.
  useEffect(() => {
    if (edgePhase !== 'no_result' || !edgeRequestRunId || !wafEdgeEnabled) return undefined;
    let cancelled = false;
    requestJson(config, session, `/v1/waf/edge-detection/${encodeURIComponent(edgeRequestRunId)}`)
      .then((payload) => { if (!cancelled) setEdgeReason(getString(payload as DataItem, ['reason'], '')); })
      .catch(() => undefined);
    return () => { cancelled = true; };
  }, [config, session, edgePhase, edgeRequestRunId, wafEdgeEnabled]);

  // Onboarding: keep re-checking a pending DNS TXT challenge so ownership (and then edge
  // detection) unlocks without the user coming back to press Check now.
  useEffect(() => {
    if (!canWrite || earlyOwnershipDone || !challenge?.id || getString(challenge as unknown as DataItem, ['state'], '') !== 'pending' || !targetGroupId) return undefined;
    const challengeId = challenge.id;
    const startedAt = Date.now();
    let busyCheck = false;
    const timer = window.setInterval(() => {
      if (busyCheck) return;
      if (Date.now() - startedAt > DNS_AUTO_RECHECK_MAX_MS) { window.clearInterval(timer); return; }
      busyCheck = true;
      verifyOwnershipChallenge(config, session, targetGroupId, challengeId)
        .then(async (result) => {
          if ((result as DataItem)?.verified === true) {
            window.clearInterval(timer);
            setBanner(wafEdgeEnabled
              ? 'Ownership proven. WAF/CDN detection is starting now.'
              : 'Ownership proven. External validation is now unlocked for this target.');
            await onRefresh().catch(() => undefined);
            await reload().catch(() => undefined);
          }
        })
        .catch(() => undefined)
        .finally(() => { busyCheck = false; });
    }, DNS_AUTO_RECHECK_MS);
    return () => window.clearInterval(timer);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [config, session, canWrite, earlyOwnershipDone, challenge?.id, challenge?.state, targetGroupId, wafEdgeEnabled]);

  const runAllDisabledReason = !targetEligible
    ? 'Prove ownership first. External probes stay blocked until this domain is at least DNS-verified.'
    : runAll.length === 0
      ? 'No runnable checks apply to this kind of target.'
      : edgeEvaluating && !scanActive
        ? 'WAF/CDN detection is running. Run all checks unlocks as soon as it finishes.'
        : '';

  async function startRunAll() {
    if (!target || runAllDisabledReason) return;
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
          name: `Run all checks · ${targetDisplayValue(target)}`.slice(0, 120),
        },
      }) as DataItem;
      setConfirmRunAll(false);
      setScan(created);
      setBanner(`Running all ${runAll.length} checks. Results appear below as each one finishes.`);
      document.getElementById('td-all-checks')?.scrollIntoView({ behavior: prefersReducedMotion() ? 'auto' : 'smooth', block: 'start' });
    } catch (err) {
      setConfirmRunAll(false);
      setError(scanErrorMessage((err as { payload?: unknown }).payload, apiErrorMessage(err, 'Run all checks could not start.')));
    } finally {
      setBusy('');
    }
  }

  const runAllRequestBound = runAll.reduce((total, check) => {
    const max = Number((check.probe_profile as DataItem | undefined)?.max_requests);
    return total + (Number.isFinite(max) ? max : 0);
  }, 0);
  const runAllCategoryCount = new Set(checkRows.map((row) => row.category.id)).size;

  function edgePhaseDetail(): { text: string; action?: ReactNode } | null {
    const detectLabel = edgePhase === 'not_started' ? 'Detect WAF and CDN' : 'Detect again';
    const retry = canStartBoundedRun && wafEdgeEnabled && !scanActive
      ? <Button size="sm" variant="secondary" onClick={() => void queueEdgeDetection()}><RefreshCw size={14} aria-hidden="true" />{detectLabel}</Button>
      : undefined;
    if (!wafEdgeEnabled && !edgeDetection) return { text: 'WAF/CDN detection is not enabled for this tenant. Run all checks still measures how the edge responds.' };
    if (edgePhase === 'locked') {
      return {
        text: 'Detection starts automatically as soon as ownership is proven. AstraNull never probes a domain you have not verified.',
        action: <Button size="sm" variant="secondary" onClick={() => document.getElementById('td-step-ownership')?.scrollIntoView({ behavior: prefersReducedMotion() ? 'auto' : 'smooth', block: 'center' })}><ShieldCheck size={14} aria-hidden="true" />Prove ownership</Button>,
      };
    }
    if (edgePhase === 'waiting') return { text: 'Another run is active in this target group. Detection starts on its own as soon as that run finishes.' };
    if (edgePhase === 'error') return { text: edgeError || 'WAF/CDN detection could not be queued.', action: retry };
    if (edgePhase === 'no_result') {
      return { text: edgeDetectionReasonExplanation(edgeReason) || 'The last detection run finished without a trusted signed-worker result, so nothing is asserted.', action: retry };
    }
    if (edgePhase === 'not_started') {
      return canStartBoundedRun
        ? { text: 'Detection has not run on this domain yet.', action: retry }
        : { text: 'Detection has not run on this domain yet. An engineer or admin can start it.' };
    }
    if (edgePhase === 'not_detected' || edgePhase === 'inconclusive') {
      const summary = getString(asDataItem(edgeDetection?.summary), ['edge'], '') || getString(edgeDetection, ['plain_language_summary'], '');
      return { text: summary || 'The last detection did not identify a WAF or CDN.', action: retry };
    }
    return null;
  }

  async function saveTags(next: string[]) {
    if (!target) return;
    await patchTargetTags(config, session, targetGroupId, entityId, next);
    setBanner('Tags saved.');
    await onRefresh();
    await reload();
  }

  async function issueOwnership() {
    if (!target) return;
    setBusy('issue');
    setError('');
    setBanner('');
    try {
      await issueOwnershipChallenge(config, session, targetGroupId, entityId);
      setBanner('DNS TXT challenge issued. Add the record below to your DNS, then choose Check now.');
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
      setBanner(verified
        ? wafEdgeEnabled
          ? 'Ownership proven. External validation is unlocked and WAF/CDN detection is starting now.'
          : 'Ownership proven. External validation is now unlocked for this target.'
        : 'The DNS TXT record was not found yet. DNS can take a few minutes to propagate, so try again shortly. This page keeps checking on its own.');
      await onRefresh();
      await reload();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not check the DNS record.');
    } finally {
      setBusy('');
    }
  }

  async function runBoundedChecks() {
    if (!canStartBoundedRun) { setError('Your role can review target evidence but cannot start validation runs.'); return; }
    if (!targetEligible || !target) { setError('Prove ownership before starting a bounded run.'); return; }
    if (!effectiveSelectedCheckId || !selectedCheck) { setError('Choose a bound check before starting a run.'); return; }
    setBusy('run');
    setError('');
    setBanner('');
    setStartedRunId('');
    try {
      const started = await verifyStartRun();
      setStartedRunId(started);
      setBanner('Bounded validation started.');
      await onRefresh();
      await reload();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to start the validation run.');
    } finally {
      setBusy('');
    }
  }

  async function verifyStartRun() {
    const started = await requestJson(config, session, '/v1/test-runs', {
      method: 'POST',
      body: { target_group_id: targetGroupId, target_id: entityId, check_id: effectiveSelectedCheckId },
    }) as { run?: { id?: unknown }; id?: unknown };
    return String(started?.run?.id ?? started?.id ?? '').trim() || 'started';
  }

  function renderHeader() {
    const hasTarget = Boolean(target);
    return (
      <div className="page-head">
        <div className="td-identity">
          <p className="eyebrow">Declared target</p>
          <h1 className="page-title mono">{hasTarget ? targetDisplayValue(target) : entityId}</h1>
          {hasTarget ? (
            <>
              <div className="td-metaline">
                <span>{formatLabel(kind)}</span>
                <span className="dot" aria-hidden="true">·</span>
                <span>Expected: {formatLabel(getString(target, ['expected_behavior', 'expected'], 'Not reported'))}</span>
                {targetGroupId ? (
                  <>
                    <span className="dot" aria-hidden="true">·</span>
                    <AnchorButton size="sm" variant="ghost" href={buildDetailHref('target-group-detail', targetGroupId)}>Group: {targetGroupName}</AnchorButton>
                  </>
                ) : null}
              </div>
              <div className="detail-status-line">
                <VerifyChip state={verificationState} provenance={provenance} label={ownershipLabel(verificationState)} />
                <span className="detail-status-sep" aria-hidden="true">·</span>
                <Badge tone={targetEligible ? 'success' : 'warn'} title={`Reported eligibility ${eligibility}; ownership ${verificationState}`}>
                  {targetEligible ? 'Validation unlocked' : 'Validation locked'}
                </Badge>
              </div>
              <span className="td-id mono muted">{entityId}</span>
              <TagEditor tags={tags} canEdit={canWrite} onChange={saveTags} />
            </>
          ) : (
            <p className="muted">Per-target validation surface.</p>
          )}
        </div>
        <div className="row-actions td-head-actions">
          {hasTarget && canStartBoundedRun && !scanActive ? (
            <Button
              disabled={Boolean(runAllDisabledReason) || busy !== ''}
              title={runAllDisabledReason || `Run all ${runAll.length} bounded checks on this domain`}
              onClick={() => setConfirmRunAll(true)}
            >
              <Play size={15} aria-hidden="true" />Run all checks
            </Button>
          ) : null}
          {hasTarget && scanActive ? (
            <AnchorButton size="sm" variant="secondary" href={buildDetailHref('scan-detail', scanId)}>
              <span className="scan-live-dot" aria-hidden="true" />Running all checks
            </AnchorButton>
          ) : null}
          <AnchorButton size="sm" variant="ghost" href="#targets">All targets</AnchorButton>
          <DesignVariantSwitch value={variant} onChange={setVariant} className="td-variant-switch" />
        </div>
      </div>
    );
  }

  if (!detail || detail.loading) {
    return (
      <div className="content target-detail-view" data-variant={variant}>
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
      : detail.error ? { empty_reason: detail.error } : null;
    return (
      <div className="content target-detail-view" data-variant={variant}>
        {renderHeader()}
        {emptyStateFromApi({ icon: Target, meta: emptyMeta, actionHref: '#targets', actionLabel: 'Back to targets' })}
      </div>
    );
  }

  const ownershipStep = ownershipStepStatus(verificationState, challenge) as { tone: StatTone; label: string; done: boolean };
  const ownershipDone = ownershipStep.done;
  const hasChecks = checksApplied.length > 0;
  const checksStepDone = hasChecks && Boolean(effectiveSelectedCheckId);
  const runDone = runsRecent.length > 0;
  // An older finding that is still open outranks a newer passing run: the result is not settled.
  const openFindings = findings.filter((finding) => isFindingOpen(finding));
  const openOriginFindings = openFindings.filter((finding) => getString(finding, ['check_id'], '').toLowerCase().startsWith('origin.')
    || getString(finding, ['title'], '').toLowerCase().includes('origin')).length;
  const verdictPassed = runOutcomeTone(latestVerdict) === 'success';
  const unresolvedAfterPass = verdictPassed && openFindings.length > 0;
  const reviewDone = Boolean(latestVerdict) && !unresolvedAfterPass;

  // Step states drive the numbered rail: done | active (first not-done) | todo.
  const stepStates = computeStepStates([true, ownershipDone, checksStepDone, runDone, reviewDone]);

  const edgeSummary = edgeSummaryLabel(edgePhase, wafEdgeEnabled || Boolean(edgeDetection));
  const summaryItems: SummaryItem[] = [
    { id: 'ownership', label: 'Ownership', value: ownershipStep.label, tone: ownershipStep.tone },
    { id: 'edge', label: 'WAF / CDN detection', value: edgeSummary.label, tone: edgeSummary.tone, note: 'Detection only, not effectiveness' },
    { id: 'checks', label: 'Bound checks', value: String(checksApplied.length), numeric: true, note: targetEligible ? 'Validation unlocked' : 'Validation locked' },
    { id: 'runs', label: 'Recorded runs', value: String(runsRecent.length), numeric: true },
    { id: 'findings', label: 'Open findings', value: String(openFindings.length), tone: openFindings.length > 0 ? 'warn' : undefined, numeric: true, note: `${findings.length} recorded in total` },
    {
      id: 'verdict',
      label: 'Latest verdict',
      value: latestVerdict ? (unresolvedAfterPass ? 'Passed, findings open' : plainVerdictLabel(latestVerdict)) : 'No verdict yet',
      tone: latestVerdict ? (unresolvedAfterPass ? 'warn' : runOutcomeTone(latestVerdict)) : 'muted',
      note: 'Evidence-backed results only',
    },
  ];

  const runColumns: TableColumn<DataItem>[] = [
    { key: 'run', label: 'Run', render: (item) => {
      const runId = getString(item, ['run_id', 'id'], '');
      const checkId = getString(item, ['check_id'], '');
      return <span className="entity-cell-stack"><DetailEntityLink route="run-detail" id={runId} label={`${displayCheckName(checkId)}`} /><small className="mono">{runId}</small></span>;
    } },
    { key: 'status', label: 'Lifecycle', render: (item) => {
      const value = getString(item, ['status', 'run_status'], 'unknown');
      return <Badge tone={runOutcomeTone(value)} title="Recorded run lifecycle">{formatLabel(value)}</Badge>;
    } },
    { key: 'verdict', label: 'Verdict', render: (item) => {
      const value = recentRunVerdict(item);
      const evidenceCount = Array.isArray(item.evidence_ids) ? item.evidence_ids.length : 0;
      return value
        ? <Badge tone={runOutcomeTone(value)} title={`Technical verdict ${value}; cites ${evidenceCount} evidence record${evidenceCount === 1 ? '' : 's'}`}>{plainVerdictLabel(value)}</Badge>
        : <span className="muted">No evidence-backed result</span>;
    } },
    { key: 'evidence', label: 'How it was checked', render: (item) => <EvidenceModeCell item={item} check={checkById.get(getString(item, ['check_id'], ''))} /> },
    { key: 'started', label: 'Started', render: (item) => formatDate(item.started_at ?? item.created_at) },
  ];

  const findingColumns: TableColumn<DataItem>[] = [
    { key: 'severity', label: 'Severity', render: (item) => formatSeverityLabel(getString(item, ['severity'], 'unknown')) },
    { key: 'id', label: 'Finding', render: (item) => <span className="entity-cell-stack"><DetailEntityLink route="finding-detail" id={getString(item, ['id'], '')} label={plainFindingTitle(item, [target], checks)} /><small className="mono">{getString(item, ['id'], '')}</small></span> },
    { key: 'state', label: 'State', render: (item) => findingStatus(item) },
    { key: 'opened', label: 'Opened', render: (item) => formatDate(item.opened_at ?? item.created_at) },
    { key: 'owner', label: 'Owner', render: (item) => getString(item, ['owner_group', 'assignee'], 'unassigned') },
  ];

  const checkColumns: TableColumn<DataItem>[] = [
    { key: 'select', label: 'Pick', render: (item) => {
      const checkId = getString(item, ['check_id', 'id'], '');
      return (
        <label className="td-check-choice">
          <input
            type="radio"
            name="target-run-check"
            value={checkId}
            checked={effectiveSelectedCheckId === checkId}
            disabled={!checkId}
            onChange={() => setSelectedCheckId(checkId)}
            aria-label={`Choose check ${displayCheckName(checkId)} for this target`}
          />
        </label>
      );
    } },
    { key: 'check', label: 'Bound check', render: (item) => { const checkId = getString(item, ['check_id', 'id'], ''); return <span className="entity-cell-stack"><strong>{displayCheckName(checkId)}</strong><small className="mono">{checkId}</small></span>; } },
    { key: 'evidence', label: 'Evidence level', render: (item) => <EvidenceModeCell item={item} check={checkById.get(getString(item, ['check_id', 'id'], ''))} /> },
  ];

  const runReasonTitle = !targetEligible
    ? 'Prove ownership to at least DNS-verified first. External probes stay blocked until then.'
    : effectiveSelectedCheckId
      ? `Run ${displayCheckName(effectiveSelectedCheckId)} now`
      : 'Choose a bound check above first.';

  const workspaceTabs = [
    { id: 'protection' as const, label: 'Protection path' },
    { id: 'edge' as const, label: 'WAF / CDN edge' },
    { id: 'runs' as const, label: 'Recent runs', count: runsRecent.length },
    { id: 'findings' as const, label: 'Findings', count: findings.length },
  ];

  const phaseDetail = edgePhaseDetail();
  const protectionCards = (
    <>
      <EdgeProtectionCard
        edge={edgeDetection}
        phase={edgePhase}
        phaseDetail={phaseDetail?.text}
        action={phaseDetail?.action}
        waf={efficacy.waf}
        cdn={efficacy.cdn}
        originExposed={efficacy.originExposed}
      />
      <AllChecksPanel
        rows={checkRows}
        declarationOnlyCount={declarationOnlyCount}
        scan={scan}
        scanActive={scanActive}
        canRun={canStartBoundedRun}
        runDisabledReason={runAllDisabledReason}
        busy={busy === 'run-all'}
        onRunAll={() => setConfirmRunAll(true)}
        onStop={() => setStopOpen(true)}
      />
    </>
  );
  const validateCard = (
        <Card>
          <CardHeader>
            <div>
              <CardTitle>Validate this target</CardTitle>
              <CardDescription>Four steps take you from a declared domain to an evidence-backed readiness verdict. Each step shows its real state and the exact next action.</CardDescription>
            </div>
            <Badge tone={targetEligible ? 'success' : 'warn'}>{targetEligible ? 'Ready to validate' : 'Ownership required'}</Badge>
          </CardHeader>
          <CardContent>
            <ol className="td-steps">
              {/* Step 1: prove ownership */}
              <li className="td-step" data-state={stepStates[1]} id="td-step-ownership">
                <div className="td-step-rail" aria-hidden="true">
                  <span className="td-step-num">{stepStates[1] === 'done' ? <Check size={15} strokeWidth={2.6} /> : 1}</span>
                  <span className="td-step-line" />
                </div>
                <div className="td-step-body">
                  <div className="td-step-head">
                    <h3>Prove ownership</h3>
                    <Badge tone={ownershipStep.tone}>{ownershipStep.label}</Badge>
                  </div>
                  <p className="td-step-why">
                    External validation probes are blocked until you prove you control this target. Ownership must reach at least DNS-verified. Publish the DNS TXT record below, then choose Check now.
                  </p>
                  {ownershipDone ? (
                    <p className="td-step-why">Verified via {ownershipMethodText(verification)}. You can move on to choosing checks.</p>
                  ) : challenge && challenge.record_name ? (
                    <>
                      <div className="td-dns">
                        <div className="td-dns-row">
                          <span className="td-dns-key">Type</span>
                          <span className="td-dns-val">TXT</span>
                          <span />
                        </div>
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
                      <div className="td-step-actions">
                        {canWrite ? (
                          <Button size="sm" loading={busy === 'verify'} disabled={busy !== ''} onClick={() => void checkOwnership()}>
                            <ShieldCheck size={15} aria-hidden="true" />Check now
                          </Button>
                        ) : <Badge tone="muted">Read-only role</Badge>}
                        {canWrite ? (
                          <Button size="sm" variant="ghost" loading={busy === 'issue'} disabled={busy !== ''} onClick={() => void issueOwnership()}>Reissue record</Button>
                        ) : null}
                        {challenge.last_checked_at ? <span className="muted small">Last checked {formatDate(challenge.last_checked_at)}</span> : null}
                      </div>
                    </>
                  ) : (
                    <div className="td-step-actions">
                      {canWrite ? (
                        <Button size="sm" loading={busy === 'issue'} disabled={busy !== ''} onClick={() => void issueOwnership()}>
                          <ShieldCheck size={15} aria-hidden="true" />Issue DNS TXT record
                        </Button>
                      ) : <Badge tone="muted">Ask an admin to prove ownership</Badge>}
                      <span className="muted small">A one-time TXT record proves you control this domain.</span>
                    </div>
                  )}
                </div>
              </li>

              {/* Step 2: choose checks */}
              <li className="td-step" data-state={stepStates[2]}>
                <div className="td-step-rail" aria-hidden="true">
                  <span className="td-step-num">{stepStates[2] === 'done' ? <Check size={15} strokeWidth={2.6} /> : 2}</span>
                  <span className="td-step-line" />
                </div>
                <div className="td-step-body">
                  <div className="td-step-head">
                    <h3>Choose a check</h3>
                    <Badge tone={effectiveSelectedCheckId ? 'success' : hasChecks ? 'warn' : 'muted'}>
                      {effectiveSelectedCheckId ? 'Selected' : hasChecks ? 'Pick one' : 'None bound'}
                    </Badge>
                  </div>
                  <p className="td-step-why">These bounded checks are bound to this target by a test policy. Pick the one you want to validate.</p>
                  {hasChecks ? (
                    <DataTable columns={checkColumns} items={checksApplied} getRowId={(item) => getString(item, ['check_id', 'id'], '')} empty={emptyStateFromApi({ icon: FileCheck2, meta: detail.sectionMeta?.checks })} />
                  ) : (
                    emptyStateFromApi({ icon: FileCheck2, meta: detail.sectionMeta?.checks })
                  )}
                </div>
              </li>

              {/* Step 3: run bounded validation */}
              <li className="td-step" data-state={stepStates[3]}>
                <div className="td-step-rail" aria-hidden="true">
                  <span className="td-step-num">{stepStates[3] === 'done' ? <Check size={15} strokeWidth={2.6} /> : 3}</span>
                  <span className="td-step-line" />
                </div>
                <div className="td-step-body">
                  <div className="td-step-head">
                    <h3>Run bounded validation</h3>
                    <Badge tone={runDone ? 'success' : 'muted'}>{runDone ? `${runsRecent.length} run${runsRecent.length === 1 ? '' : 's'}` : 'Not run yet'}</Badge>
                  </div>
                  <p className="td-step-why">
                    {targetEligible
                      ? 'Rate-limited external probes run against this target and produce evidence. Nothing runs until you start it.'
                      : 'This action stays disabled until ownership is proven. AstraNull will not aim probes at a target you have not verified.'}
                  </p>
                  <div className="td-step-actions">
                    {canStartBoundedRun ? (
                      <Button
                        className={targetEligible && effectiveSelectedCheckId ? undefined : 'is-locked'}
                        disabled={!targetEligible || !effectiveSelectedCheckId || busy !== ''}
                        title={runReasonTitle}
                        loading={busy === 'run'}
                        onClick={() => void runBoundedChecks()}
                      >
                        <Play size={15} aria-hidden="true" />Run selected check
                      </Button>
                    ) : <Badge tone="muted">Read-only role</Badge>}
                    {!targetEligible ? <span className="muted small">Locked until ownership is proven in step 1.</span> : !effectiveSelectedCheckId ? <span className="muted small">Choose a check in step 2.</span> : null}
                  </div>
                </div>
              </li>

              {/* Step 4: review results */}
              <li className="td-step" data-state={stepStates[4]}>
                <div className="td-step-rail" aria-hidden="true">
                  <span className="td-step-num">{stepStates[4] === 'done' ? <Check size={15} strokeWidth={2.6} /> : 4}</span>
                </div>
                <div className="td-step-body">
                  <div className="td-step-head">
                    <h3>Review results</h3>
                    {latestVerdict
                      ? unresolvedAfterPass
                        ? <Badge tone="warn">{`Passed · ${openFindings.length} open finding${openFindings.length === 1 ? '' : 's'}`}</Badge>
                        : <Badge tone={runOutcomeTone(latestVerdict)}>{plainVerdictLabel(latestVerdict)}</Badge>
                      : <Badge tone="muted">No verdict yet</Badge>}
                  </div>
                  {latestVerdict ? (
                    <div className="td-verdict">
                      <p>
                        {unresolvedAfterPass
                          ? `The latest run passed, but ${openFindings.length === 1 ? 'a finding' : `${openFindings.length} findings`} from earlier evidence ${openFindings.length === 1 ? 'is' : 'are'} still open. Confirm the fix is in place, then close ${openFindings.length === 1 ? 'it' : 'them'} in Findings.`
                          : plainVerdictDescription(latestVerdict) || 'This verdict is backed by recorded probe evidence. Open the run for the full evidence trail.'}
                      </p>
                      {latestVerdictRun ? <DetailEntityLink route="run-detail" id={getString(latestVerdictRun, ['run_id', 'id'], '')} label="Open evidence" /> : null}
                      {findings.length > 0 ? (
                        <Button size="sm" variant="ghost" onClick={() => setTab('findings')}>
                          <TriangleAlert size={14} aria-hidden="true" />{findings.length} finding{findings.length === 1 ? '' : 's'}
                        </Button>
                      ) : null}
                    </div>
                  ) : (
                    <p className="td-step-why">Once a bounded run finishes, the latest evidence-backed verdict and any findings appear here in plain language.</p>
                  )}
                </div>
              </li>
            </ol>
          </CardContent>
        </Card>
  );

  return (
    <div className="content target-detail-view" data-variant={variant}>
      {renderHeader()}
      {error ? <div className="form-banner error" role="alert">{error}</div> : null}
      {banner && !error ? <div className="form-banner" role="status">{banner}{startedRunId && startedRunId !== 'started' ? <> <DetailEntityLink route="run-detail" id={startedRunId} label="Open run" /></> : null}</div> : null}

      {variant === 'premium' ? <SummaryStrip items={summaryItems} /> : null}

      <div className="td-layout">
      <div className="td-main">
      {targetEligible ? (<>{protectionCards}{validateCard}</>) : (<>{validateCard}{protectionCards}</>)}

      <Card className="td-evidence-card">
        <CardHeader>
          <div>
            <CardTitle>Evidence &amp; posture</CardTitle>
            <CardDescription>Everything recorded for this target: what protects it, edge fingerprints, run history, and open findings.</CardDescription>
          </div>
        </CardHeader>
        <CardContent>
          <Tabs
            ariaLabel="Target evidence and posture"
            value={tab}
            options={workspaceTabs}
            onChange={setTab}
            getPanelId={(id) => `td-panel-${id}`}
            getTabId={(id) => `td-tab-${id}`}
          />
          <div className="td-panel" role="tabpanel" id={`td-panel-${tab}`} aria-labelledby={`td-tab-${tab}`}>
            {tab === 'protection' ? <ProtectionPanel detail={detail} openOriginFindings={openOriginFindings} /> : null}
            {tab === 'edge' ? <EdgePanel detail={detail} /> : null}
            {tab === 'runs' ? (
              <DataTable columns={runColumns} items={runsRecent} empty={emptyStateFromApi({ icon: Activity, meta: detail.sectionMeta?.runs, actionHref: '#runs', actionLabel: 'Open test runs' })} />
            ) : null}
            {tab === 'findings' ? (
              <DataTable columns={findingColumns} items={findings} empty={emptyStateFromApi({ icon: TriangleAlert, meta: detail.sectionMeta?.findings, actionHref: '#findings', actionLabel: 'Open findings' })} />
            ) : null}
          </div>
        </CardContent>
      </Card>
      </div>

      <div className="td-rail">
      <Card className="td-facts">
        <CardHeader>
          <div>
            <CardTitle>Target facts</CardTitle>
            <CardDescription>Declared inventory, ownership evidence, and authorization for this target.</CardDescription>
          </div>
        </CardHeader>
        <CardContent>
          <div className="table-wrap" tabIndex={0} role="region" aria-label="Target facts, scrollable">
            <table className="data-table">
              <tbody>
                <tr><td className="muted">Target ID</td><td><span className="mono">{entityId}</span></td></tr>
                <tr><td className="muted">Declared value</td><td><span className="mono">{targetDisplayValue(target)}</span></td></tr>
                <tr><td className="muted">Kind</td><td>{formatLabel(kind)}</td></tr>
                <tr><td className="muted">Declaration source</td><td>{plainCheckName(targetDeclarationProvenanceLabel(target))}</td></tr>
                <tr><td className="muted">Ownership method</td><td><span className="mono">{ownershipMethodText(verification)}</span></td></tr>
                <tr><td className="muted">Ownership status</td><td><VerifyChip state={verificationState} provenance={provenance} label={ownershipLabel(verificationState)} /></td></tr>
                <tr><td className="muted">Target group</td><td><DetailEntityLink route="target-group-detail" id={targetGroupId} label={targetGroupName} /></td></tr>
                <tr><td className="muted">Expected behavior</td><td>{formatLabel(getString(target, ['expected_behavior', 'expected'], 'Not reported'))}</td></tr>
                <tr><td className="muted">Tags</td><td>{tags.length ? <span className="mono">{tags.join(', ')}</span> : <span className="muted">None</span>}</td></tr>
                {detail.loa ? (
                  <tr><td className="muted">Group LOA</td><td><Badge tone={getString(detail.loa, ['state'], '') === 'signed' ? 'success' : 'warn'}>{formatLabel(getString(detail.loa, ['state'], 'Not reported'))}</Badge></td></tr>
                ) : null}
              </tbody>
            </table>
          </div>
          {ownershipHistory.length > 0 ? (
            <details className="td-history technical-disclosure">
              <summary>Show recorded verification transitions</summary>
              <DataTable
                columns={[
                  { key: 'state', label: 'Recorded state', render: (item) => <VerifyChip state={getString(item, ['state'], 'unknown')} provenance={`Recorded transition ${getString(item, ['state'], 'unknown')}`} label={ownershipLabel(getString(item, ['state'], 'unknown'))} /> },
                  { key: 'transitioned', label: 'Transitioned', render: (item) => item.transitioned_at ? formatDate(item.transitioned_at) : <span className="muted">Not reported</span> },
                ]}
                items={ownershipHistory}
                getRowId={(item, index) => `${getString(item, ['state'], 'unknown')}-${index}`}
                empty={<span className="muted">No verification transitions reported.</span>}
              />
            </details>
          ) : null}
        </CardContent>
      </Card>
      </div>
      </div>

      <ConfirmModal
        open={confirmRunAll}
        title={`Run all ${runAll.length} checks on ${targetDisplayValue(target)}?`}
        description={(
          <div className="stack-tight scan-review">
            <p><strong>{runAll.length} bounded external checks</strong> across {runAllCategoryCount} categories, at most {runAllRequestBound} probe requests in total.</p>
            <p>WAF/CDN detection and origin exposure run first, then one check at a time. Each result appears on this page as it lands.</p>
            <p>The run paces itself inside your safe-run limits. If an hourly limit is reached it pauses and shows when it resumes.</p>
            <p>Other runs in this target group wait until it finishes. You can stop it at any time.</p>
            {declarationOnlyCount > 0 ? <p className="muted small">{declarationOnlyCount} declaration-only checks are skipped because they send no traffic.</p> : null}
          </div>
        )}
        confirmLabel="Run all checks"
        confirmTone="default"
        busy={busy === 'run-all'}
        onCancel={() => setConfirmRunAll(false)}
        onConfirm={() => void startRunAll()}
      />
      <CancelScanDialog
        scan={stopOpen ? scan : null}
        config={config}
        session={session}
        onClose={() => setStopOpen(false)}
        onCancelled={(result) => {
          setStopOpen(false);
          setScan(result);
          setBanner('Run all checks stopped. Finished results are kept.');
          void loadTargetActivity();
        }}
      />
    </div>
  );
}

/** first not-done step is 'active'; earlier are 'done'; later are 'todo'. index 0 (declared) is always done. */
function computeStepStates(done: boolean[]): Array<'done' | 'active' | 'todo'> {
  const firstPending = done.findIndex((d) => !d);
  return done.map((d, index) => {
    if (d) return 'done';
    if (index === firstPending) return 'active';
    return 'todo';
  });
}

function ProtectionPanel({ detail, openOriginFindings = 0 }: { detail: TargetDetailPayload; openOriginFindings?: number }) {
  const wafPosture = detail.waf_posture;
  const edgeDetection = detail.edge_detection;
  const edgeWaf = asDataItem(edgeDetection?.waf);
  const edgeCdn = asDataItem(edgeDetection?.cdn);
  const edgeCloud = asDataItem(edgeDetection?.cloud);
  const originBypass = asDataItem(wafPosture?.origin_bypass);
  const wafPostureState = getString(wafPosture, ['posture', 'status'], '');
  const wafLayerState = getString(edgeWaf, ['status'], wafPostureState || 'unknown');
  const cdnLayerState = getString(edgeCdn, ['status'], 'unknown');
  const cloudLayerState = getString(edgeCloud, ['status'], 'unknown');
  // A still-open origin finding means the last clean check is not the whole story.
  const originLayerState = openOriginFindings > 0 ? 'inconclusive' : getString(originBypass, ['state'], 'unknown');

  const apiSummary = getString(edgeDetection, ['plain_language_summary', 'protection_summary'], '')
    || getString(wafPosture, ['plain_language_summary', 'protection_summary'], '');
  const summary = apiSummary
    || (edgeDetection
      ? 'A live edge check recorded the layers below. Detection alone does not prove they blocked a test.'
      : wafPosture
        ? `Linked WAF posture is available: ${plainProtectionLabel(wafPostureState)}. Open the evidence before treating it as a broad readiness claim.`
        : 'Protection layers have not been tested live for this target yet. Run a bounded validation to gather evidence.');

  const layers = [
    { icon: ShieldCheck, label: 'Web application firewall', state: wafLayerState, detail: getString(edgeWaf, ['provider'], getString(wafPosture, ['vendor'], '')) ? `Provider: ${getString(edgeWaf, ['provider'], getString(wafPosture, ['vendor'], ''))}.` : 'No WAF provider asserted.' },
    { icon: Network, label: 'CDN / edge network', state: cdnLayerState, detail: getString(edgeCdn, ['provider'], '') ? `Provider: ${getString(edgeCdn, ['provider'], '')}.` : 'No CDN provider asserted by a live edge result.' },
    { icon: Cloud, label: 'Cloud hosting', state: cloudLayerState, detail: getString(edgeCloud, ['provider'], '') ? `Hosting matched ${getString(edgeCloud, ['provider'], '')}; hosting is not proof of protection.` : 'Hosting not asserted; hosting alone would not prove protection.' },
    { icon: Server, label: 'Origin access', state: originLayerState, detail: openOriginFindings > 0
      ? `${openOriginFindings} open origin finding${openOriginFindings === 1 ? '' : 's'} still recorded; close ${openOriginFindings === 1 ? 'it' : 'them'} after confirming the fix.`
      : originBypass?.last_checked_at ? `Last direct-path check: ${formatDate(originBypass.last_checked_at)}.` : 'Direct-origin reachability not reported as tested.' },
  ];

  return (
    <>
      <p className="td-protection-lede">{summary}</p>
      <div className="td-protection-grid" aria-label="Detected and reported protection layers">
        {layers.map((layer) => (
          <section key={layer.label} className="td-layer" aria-label={`${layer.label}: ${plainProtectionLabel(layer.state)}`}>
            <div className="td-layer-head"><layer.icon size={16} aria-hidden="true" /><strong>{layer.label}</strong></div>
            <Badge tone={protectionStateTone(layer.state)} title={layer.state !== 'unknown' ? `Recorded state: ${plainCodeLabel(layer.state)}.` : undefined}>{plainProtectionLabel(layer.state)}</Badge>
            <p>{layer.detail}</p>
          </section>
        ))}
      </div>
      <EvidenceGuide compact />
    </>
  );
}

function EdgePanel({ detail }: { detail: TargetDetailPayload }) {
  const edgeDetection = detail.edge_detection;
  if (!edgeDetection) {
    return <p className="muted">No edge detection has been recorded for this target yet. Run a WAF/CDN detection check to populate this section.</p>;
  }
  const edgeStatus = getString(edgeDetection, ['status'], 'inconclusive');
  const edgeReason = getString(edgeDetection, ['reason'], '');
  const reasonExplanation = edgeDetectionReasonExplanation(edgeReason);
  const edgeWaf = asDataItem(edgeDetection.waf);
  const edgeCdn = asDataItem(edgeDetection.cdn);
  const edgeCloud = asDataItem(edgeDetection.cloud);
  const evidence = asDataItem(edgeDetection.evidence);
  const cnameChain = stringList(evidence?.dns_cname_chain);
  const resolvedIps = stringList(evidence?.dns_resolved_ips);
  const families: Array<{ title: string; row: DataItem | null }> = [
    { title: 'WAF', row: edgeWaf }, { title: 'CDN', row: edgeCdn }, { title: 'Cloud hosting', row: edgeCloud },
  ];
  return (
    <>
      <div className="detail-status-line">
        <Badge tone={edgeStatusTone(edgeStatus)} title={`Edge detection status ${edgeStatus}${edgeReason ? ` · reason ${edgeReason}` : ''}`}>{plainProtectionLabel(edgeStatus)}</Badge>
        {edgeReason ? <span className="muted small">{reasonExplanation || `Reason: ${formatLabel(edgeReason)}.`}</span> : null}
      </div>
      <div className="td-edge-grid" aria-label="Independent WAF, CDN, and cloud hosting detection">
        {families.map(({ title, row }) => (
          <section key={title} className="td-edge-card" aria-label={`${title} detection`}>
            <div className="td-edge-card-head">
              <strong>{title}</strong>
              <Badge tone={edgeStatusTone(getString(row, ['status'], 'inconclusive'))}>{formatLabel(getString(row, ['status'], 'inconclusive'))}</Badge>
            </div>
            <dl>
              <dt>Provider</dt><dd>{getString(row, ['provider'], 'Not asserted')}</dd>
              <dt>Type</dt><dd>{formatLabel(getString(row, ['type'], ''), 'Not reported')}</dd>
            </dl>
          </section>
        ))}
      </div>
      {cnameChain.length > 0 ? <p className="td-edge-chain"><span className="lbl">CNAME chain</span><span className="mono">{cnameChain.join(' → ')}</span></p> : null}
      {resolvedIps.length > 0 ? <p className="td-edge-chain"><span className="lbl">Resolved addresses</span><span className="mono">{resolvedIps.join(', ')}</span></p> : null}
      <p className="muted small">Fingerprint detection is not a protection verdict. A no-match does not prove that no edge control exists.</p>
    </>
  );
}
