import { useMemo, useRef, useState, type ReactNode } from 'react';
import {
  Activity,
  Ban,
  Bell,
  Bug,
  ChevronRight,
  CircleCheck,
  CircleDashed,
  CircleMinus,
  CircleX,
  Eye,
  Fingerprint,
  Globe,
  Hourglass,
  LoaderCircle,
  Lock,
  Network,
  Play,
  Radio,
  Server,
  Shield,
  ShieldCheck,
  Square,
  Waves,
  Waypoints,
  Workflow,
  type LucideIcon,
} from 'lucide-react';
import type { DataItem } from '../../lib/types';
import { formatDate } from '../../lib/utils';
import { plainVerdictLabel } from '../../lib/plain-language.mjs';
import { formatStepRequest, formatStepResponse, humanizeReason } from '../../lib/validation-scan.mjs';
import {
  MAX_SCAN_CHECKS,
} from '../../lib/validation-scan.mjs';
import {
  ROW_STATUS_META,
  groupRowsByCategory,
  rowProgress,
  type CategoryIcon,
  type CheckRow,
  type MarkerEffectiveness,
  type ProviderFamilyRow,
  type RowStatus,
  type WafCheckBlocking,
} from '../../lib/domain-checks.mjs';
import { buildScanLiveLogs, generateCheckProbeLogs } from '../../lib/live-probe-logs';
import { Badge } from '../ui/badge';
import { Button } from '../ui/button';
import { Progress } from '../ui/progress';
import { ProviderLogo, type ProviderLogoId } from '../integrations/provider-logos';
import { LiveProbeTerminal } from './live-probe-terminal';

const CATEGORY_ICONS: Record<CategoryIcon, LucideIcon> = {
  shield: ShieldCheck,
  bug: Bug,
  server: Server,
  globe: Globe,
  workflow: Workflow,
  lock: Lock,
  network: Network,
  dns: Waypoints,
  radio: Radio,
  waves: Waves,
  activity: Activity,
  bell: Bell,
};

const STATUS_ICONS: Record<RowStatus, LucideIcon> = {
  passed: CircleCheck,
  failed: CircleX,
  inconclusive: CircleMinus,
  observed: Eye,
  running: LoaderCircle,
  queued: CircleDashed,
  waiting: Hourglass,
  blocked: Ban,
  skipped: CircleMinus,
  cancelled: CircleMinus,
  not_run: CircleDashed,
};

const TIER_COPY: Record<string, string> = {
  E2: 'Connection observed',
  E3: 'Behavior observed',
};

type QueueFilter = 'all' | 'verdict' | RowStatus;

const FILTERS: Array<{ id: QueueFilter; label: string }> = [
  { id: 'all', label: 'All' },
  { id: 'verdict', label: 'Produces a verdict' },
  { id: 'failed', label: ROW_STATUS_META.failed.label },
  { id: 'passed', label: ROW_STATUS_META.passed.label },
  { id: 'inconclusive', label: 'Inconclusive' },
  { id: 'observed', label: 'Observed' },
  { id: 'running', label: 'Running' },
  { id: 'waiting', label: 'Waiting' },
  { id: 'queued', label: 'Queued' },
  { id: 'blocked', label: 'Safety gate' },
  { id: 'not_run', label: 'Not run' },
];

const ORIGIN_COPY: Record<string, { label: string; tone: 'muted' | 'danger' | 'success' | 'warn'; detail: string }> = {
  not_tested: { label: 'Not tested', tone: 'muted', detail: 'No authorized check has tested a declared origin for this target.' },
  reachable: { label: 'Origin response observed', tone: 'danger', detail: 'A declared origin answered the recorded direct request, so the direct path is reachable for that scope. Application identity is shown in the check evidence.' },
  exposed: { label: 'Origin response observed', tone: 'danger', detail: 'A declared origin answered the recorded direct request, so the direct path is reachable for that scope. Application identity is shown in the check evidence.' },
  denied: { label: 'Explicit denial observed', tone: 'muted', detail: 'The declared origin explicitly denied the recorded direct request for this host, path, source and time. The responsible control is not identified.' },
  unreachable: { label: 'No response; enforcement unverified', tone: 'warn', detail: 'An earlier check version recorded no direct answer. Silence does not prove a firewall or lockdown is enforcing; rerun the current check version.' },
  not_reachable: { label: 'No response; enforcement unverified', tone: 'warn', detail: 'The declared origin did not answer the recorded direct request. Silence does not prove a firewall or lockdown is enforcing.' },
  inconclusive: { label: 'Inconclusive', tone: 'warn', detail: 'The recorded origin check did not reach a conclusion.' },
  unknown: { label: 'Reachability recorded, no assurance', tone: 'muted', detail: 'A direct-origin reachability result is recorded, but no authorized origin binding exists, so it is not an origin lockdown.' },
};

function Spinner({ size = 16 }: { size?: number }) {
  return <LoaderCircle size={size} className="td-spin" aria-hidden="true" />;
}

export type ProviderObservationsProps = {
  rows: ProviderFamilyRow[];
  effectiveness: MarkerEffectiveness | null;
  originStatus: string;
  originDetail?: { assurance: string; reachabilityStatus: string; testedTargetId: string; scenarioId: string; limitations: string[] };
  evaluating: boolean;
  note?: ReactNode;
  action?: ReactNode;
  onInspect: (row: ProviderFamilyRow) => void;
  /** Recorded outcomes of this target's benign WAF marker checks; null when none has a result. */
  checkBlocking?: WafCheckBlocking | null;
  onOpenChecks?: () => void;
};

/** Flat, ruled list: one row per family, each from its own recorded source only. */
export function ProviderObservations({ rows, effectiveness, originStatus, originDetail, evaluating, note, action, onInspect, checkBlocking = null, onOpenChecks }: ProviderObservationsProps) {
  const edgeProxyRow = rows.find(
    (r) => (r.family === 'cdn' || r.family === 'waf') && r.status === 'detected'
  );
  const hasEdgeProxy = Boolean(edgeProxyRow);
  const detectedProxyName = edgeProxyRow?.providerName || (rows.find((r) => r.providerName)?.providerName ?? '');

  const origin = hasEdgeProxy && originStatus === 'not_tested'
    ? {
        label: 'Masked (Not tested)',
        tone: 'muted' as const,
        detail: `Origin is masked behind ${detectedProxyName || 'the edge proxy'}. Bind an origin under Origin Relations to test direct reachability.`,
      }
    : (ORIGIN_COPY[originStatus] ?? { label: humanizeReason(originStatus) || 'Not recorded', tone: 'muted' as const, detail: '' });
  return (
    <section className="td-observations" aria-labelledby="td-observations-title" aria-busy={evaluating || undefined}>
      <header className="td-section-head">
        <div>
          <h2 id="td-observations-title">Protection observations</h2>
          <p>Who serves this endpoint, from external fingerprints. Detection is a signal, not proof of blocking.</p>
        </div>
        {action}
      </header>
      {note ? <div className="td-callout">{note}</div> : null}
      <ul className="td-provider-list">
        {rows.map((row) => {
          let statusLabel = row.statusLabel;
          let metaText = '';

          if (hasEdgeProxy && row.family === 'cloud' && (row.status === 'not_detected' || row.status === 'not_recorded')) {
            statusLabel = 'Masked by edge proxy';
            metaText = `Public traffic routes through ${detectedProxyName || 'the edge proxy'}; direct cloud hosting layer is masked.`;
          } else if (hasEdgeProxy && row.family === 'origin_hosting' && (row.status === 'unknown' || row.status === 'not_recorded')) {
            statusLabel = 'Unknown · Masked';
            metaText = `Origin server is masked behind ${detectedProxyName || 'the edge proxy'}. Bind an origin under Origin Relations to test.`;
          } else if (hasEdgeProxy && row.family === 'dns' && (row.status === 'unknown' || row.status === 'not_recorded')) {
            statusLabel = row.statusLabel;
            metaText = detectedProxyName
              ? `No DNS connector configured; authoritative DNS is managed or masked behind ${detectedProxyName}.`
              : 'No DNS connector configured in Integrations; authoritative DNS not recorded.';
          } else {
            const timeText = row.observedAt
              ? `Observed ${formatDate(row.observedAt)}`
              : row.source === 'none' || ['not_checked', 'not_recorded', 'unknown'].includes(row.status)
                ? 'No recorded observation'
                : 'Observation time not recorded';
            const sourceText = row.sources.length
              ? ` · ${row.sources.map((source) => source.method).join(', ')}`
              : row.status === 'detected'
                ? ' · Source not recorded'
                : '';
            metaText = `${timeText}${sourceText}`;
          }

          return (
            <li key={row.family} className="td-provider-row" data-status={row.status}>
              <span className="td-provider-mark" aria-hidden="true">
                {row.logo ? <ProviderLogo provider={row.logo as ProviderLogoId} size={20} /> : <Shield size={18} />}
              </span>
              <span className="td-provider-copy">
                <span className="td-provider-title">{row.title}</span>
                <span className="td-provider-value">
                  {evaluating && row.source === 'none' && (row.family === 'waf' || row.family === 'cdn') ? (
                    <span className="td-evaluating"><Spinner size={14} />Detection running</span>
                  ) : (
                    <>
                      <Badge tone={row.tone}>{statusLabel}</Badge>
                      {row.providerName ? <strong>{row.providerName}</strong> : null}
                      {row.freshness === 'stale' ? <span className="td-provider-stale">Stale</span> : null}
                    </>
                  )}
                </span>
                <span className="td-provider-meta">{metaText}</span>
              </span>
              <Button
                size="sm"
                variant="ghost"
                className="td-provider-inspect"
                data-focus-key={`provider-${row.family}`}
                aria-label={`How ${row.title} was identified`}
                onClick={() => onInspect(row)}
              >
                <Fingerprint size={14} aria-hidden="true" />
                {row.source === 'none' || ['not_checked', 'not_recorded', 'unknown'].includes(row.status) ? 'What we know' : 'How identified'}
              </Button>
            </li>
          );
        })}
        <li className="td-provider-row" data-status={originStatus}>
          <span className="td-provider-mark" aria-hidden="true"><Server size={18} /></span>
          <span className="td-provider-copy">
            <span className="td-provider-title">Origin exposure</span>
            <span className="td-provider-value"><Badge tone={origin.tone}>{origin.label}</Badge></span>
            <span className="td-provider-meta">
              {origin.detail}
              {originDetail && originDetail.reachabilityStatus && originDetail.reachabilityStatus !== 'not_tested' ? ` Recorded reachability: ${humanizeReason(originDetail.reachabilityStatus).toLowerCase()}${originDetail.testedTargetId ? ` for tested target ${originDetail.testedTargetId}` : ''}${originDetail.scenarioId ? `, scenario ${originDetail.scenarioId}` : ''}.` : ''}
              {originDetail && originDetail.assurance && originDetail.assurance !== 'none' && originDetail.assurance !== 'not_recorded' ? ` Origin assurance: ${humanizeReason(originDetail.assurance).toLowerCase()}.` : ''}
              {originDetail?.limitations?.length ? ` Limits: ${originDetail.limitations.map((item) => humanizeReason(item).toLowerCase()).join(', ')}.` : ''}
            </span>
          </span>
          <span />
        </li>
      </ul>
      <div className="td-effectiveness">
        <span className="td-label">Benign marker blocking</span>
        {checkBlocking ? (
          <div className="td-effectiveness-line">
            <p>
              From WAF marker checks: <strong className="tabular-nums">{checkBlocking.stopped}</strong> stopped the test traffic ·{' '}
              <strong className="tabular-nums">{checkBlocking.allowed}</strong> allowed ·{' '}
              <span className="tabular-nums">{checkBlocking.inconclusive}</span> inconclusive ·{' '}
              <span className="tabular-nums">{checkBlocking.notRun}</span> not run (of <span className="tabular-nums">{checkBlocking.applicable}</span>)
              {checkBlocking.lastAt ? <span className="td-muted"> · last result {formatDate(checkBlocking.lastAt)}</span> : null}
            </p>
            {onOpenChecks ? <Button size="sm" variant="ghost" onClick={onOpenChecks}>Review WAF checks</Button> : null}
          </div>
        ) : null}
        {effectiveness ? (
          <p>
            During the fingerprint scan: <strong className="tabular-nums">{effectiveness.blocked}</strong> blocked ·{' '}
            <strong className="tabular-nums">{effectiveness.allowed}</strong> allowed ·{' '}
            <span className="tabular-nums">{effectiveness.inconclusive}</span> inconclusive
            {effectiveness.percentage !== null
              ? <> · <span className="tabular-nums">{effectiveness.percentage}%</span> of definitive markers</>
              : <> · no definitive markers, so no percentage</>}
          </p>
        ) : null}
        {!checkBlocking && !effectiveness ? (
          <p className="td-muted">Not measured. Detection alone does not show whether anything is blocked.</p>
        ) : null}
      </div>
    </section>
  );
}

function rowRequestLine(row: CheckRow) {
  if (row.request) return formatStepRequest(row.request);
  const parts = [humanizeReason(row.probeKind)];
  if (row.maxRequests !== null) parts.push(`at most ${row.maxRequests} request${row.maxRequests === 1 ? '' : 's'}`);
  if (row.timeoutMs !== null) parts.push(`${row.timeoutMs} ms timeout`);
  return parts.filter(Boolean).join(' · ') || 'Bounded probe profile not recorded';
}

function rowSentLine(row: CheckRow) {
  if (row.requestsSimulated) return `${row.requestsSent ?? 0} (simulated, no live traffic)`;
  if (row.requestsSent === null || row.requestsSent === undefined) return '';
  return String(row.requestsSent);
}

function rowResultLine(row: CheckRow) {
  if (row.status === 'waiting') return row.eligibleAt ? `Paused by a safety limit; resumes ${formatDate(row.eligibleAt)}.` : 'Paused by a safety limit.';
  if (row.status === 'blocked') return row.reason ? `A safety gate stopped this check: ${humanizeReason(row.reason).toLowerCase()}.` : 'A safety gate stopped this check.';
  if (row.status === 'running') return 'Awaiting the recorded response.';
  if (row.status === 'queued') return 'Queued. Checks run one at a time.';
  if (row.status === 'not_run') return 'Not run on this target yet.';
  if (row.status === 'skipped' || row.status === 'cancelled') return row.reason ? humanizeReason(row.reason) : `${row.label}.`;
  if (row.status === 'observed') return row.explanation || 'Recorded transport behavior. Transport-only checks inform the picture but never decide a verdict.';
  return row.explanation || (row.verdict ? plainVerdictLabel(row.verdict) : row.label);
}

function CheckQueueRow({
  row,
  selected,
  onSelect,
  included,
  canInclude,
  onToggleInclude,
  onInspect,
  onStopCheck,
  onActivity,
  liveNote,
  targetValue,
  runEvents,
}: {
  row: CheckRow;
  selected: boolean;
  onSelect: (checkId: string) => void;
  included: boolean;
  canInclude: boolean;
  onToggleInclude?: (checkId: string) => void;
  onInspect: (row: CheckRow) => void;
  onStopCheck?: (row: CheckRow) => void;
  onActivity?: (row: CheckRow) => void;
  /** Set when the server says this pair's result is retained, not current live external evidence. */
  liveNote?: string;
  targetValue?: string;
  runEvents?: DataItem[];
}) {
  const StatusIcon = STATUS_ICONS[row.status] ?? CircleDashed;
  const sent = rowSentLine(row);
  const resultType = row.readinessCapable ? 'Produces a verdict' : 'Observation only — no verdict';
  return (
    <li className="td-check" data-status={row.status} data-selected={selected || undefined} data-included={included || undefined} data-focus-key={`check-${row.checkId}`}>
      <div className="td-check-row">
        {onToggleInclude ? (
          <label className="td-check-choice">
            <input
              type="checkbox"
              name="target-run-check"
              value={row.checkId}
              checked={included}
              disabled={!canInclude}
              onChange={() => onToggleInclude(row.checkId)}
              aria-label={`Include ${row.name} in run`}
            />
          </label>
        ) : <span className="td-check-choice" aria-hidden="true" />}
        <button type="button" className="td-check-summary" aria-expanded={selected} onClick={() => onSelect(row.checkId)}>
          <span className="td-check-icon" data-tone={row.tone}>
            <StatusIcon size={16} className={row.status === 'running' ? 'td-spin' : undefined} aria-hidden="true" />
          </span>
          <span className="td-check-name">
            <strong>{row.name}</strong>
            <code>{row.checkId}</code>
          </span>
          <span className="td-check-tier">{TIER_COPY[row.tier] ? `${TIER_COPY[row.tier]} · ` : ''}{resultType}</span>
          <Badge tone={liveNote ? 'muted' : row.tone}>{row.label}</Badge>
          {liveNote ? <Badge tone="warn" title={liveNote}>Not live evidence</Badge> : null}
          <ChevronRight size={16} className="td-chevron" aria-hidden="true" />
        </button>
      </div>
      {selected ? (
        <div className="td-check-open">
          <dl className="td-check-detail">
            <div><dt>How it works</dt><dd>{row.description || row.category.how}</dd></div>
            {row.verdictLogic ? <div><dt>How it decides</dt><dd>{row.verdictLogic}</dd></div> : null}
            <div><dt>Result type</dt><dd>{row.readinessCapable ? 'Produces a readiness verdict' : 'Observation only — no readiness credit'}</dd></div>
            <div><dt>Upper bound</dt><dd>{rowRequestLine(row)}</dd></div>
            {sent ? <div><dt>Requests sent</dt><dd className="tabular-nums">{sent}</dd></div> : null}
            {row.response ? <div><dt>Response</dt><dd>{formatStepResponse(row.response)}</dd></div> : null}
            <div>
              <dt>Result</dt>
              <dd>
                {row.status === 'running' ? (
                  <span className="td-live-result-line">
                    <span className="td-pulse-beacon-inline" aria-hidden="true" />
                    <strong>Awaiting recorded response</strong>
                    <span className="td-muted">{row.requestsSent != null ? ` · ${row.requestsSent}${row.maxRequests != null ? `/${row.maxRequests}` : ''} requests sent` : ' · Request count not recorded yet'}</span>
                  </span>
                ) : (
                  rowResultLine(row)
                )}
              </dd>
            </div>
            {liveNote ? <div><dt>Coverage</dt><dd>Retained record, not counted as current live external evidence: {liveNote}.</dd></div> : null}
            {row.finishedAt || row.startedAt ? <div><dt>{row.finishedAt ? 'Finished' : 'Started'}</dt><dd>{formatDate(row.finishedAt || row.startedAt)}</dd></div> : null}
          </dl>
          <div className="td-check-terminal-wrapper">
            <LiveProbeTerminal
              entries={generateCheckProbeLogs(row, targetValue, runEvents)}
              active={row.status === 'running'}
              title={`Probe execution logs · ${row.checkId}`}
              activeCheckLabel={row.checkId}
              requestsSent={row.requestsSent}
              maxRequests={row.maxRequests}
              compact
              emptyMessage="No probe execution logs recorded for this check yet."
            />
          </div>
          <div className="td-check-links">
            {row.runId || ['blocked', 'skipped', 'cancelled'].includes(row.status) ? <Button size="sm" variant="ghost" onClick={() => onActivity?.(row)}>View activity</Button> : null}
            {row.runId && row.status === 'running' && onStopCheck ? <Button size="sm" variant="danger" aria-label={`Stop ${row.name}`} onClick={() => onStopCheck(row)}><Square size={13} aria-hidden="true" />Stop this check</Button> : null}
            {row.runId ? (
              <Button size="sm" variant="secondary" data-focus-key={`check-evidence-${row.checkId}`} onClick={() => onInspect(row)}>
                <Eye size={14} aria-hidden="true" />View evidence
              </Button>
            ) : <span className="td-muted">No recorded result to inspect yet.</span>}
          </div>
        </div>
      ) : null}
    </li>
  );
}

function CategorySelect({ label, ids, selection, disabled, onChange }: { label: string; ids: string[]; selection: Set<string>; disabled: boolean; onChange: (ids: string[], include: boolean) => void }) {
  const includedCount = ids.filter((id) => selection.has(id)).length;
  const all = ids.length > 0 && includedCount === ids.length;
  const some = includedCount > 0 && !all;
  return (
    <label className="td-cat-select">
      <input
        type="checkbox"
        checked={all}
        disabled={disabled || ids.length === 0}
        ref={(element) => { if (element) element.indeterminate = some; }}
        onChange={() => onChange(ids, !all)}
        aria-label={`Select all in ${label}`}
      />
    </label>
  );
}

export type CheckQueueProps = {
  rows: CheckRow[];
  runAllCount?: number;
  catalogCount?: number;
  selectedCheckId: string;
  canSelect: boolean;
  onSelect: (checkId: string) => void;
  onInspect: (row: CheckRow) => void;
  scan: DataItem | null;
  scanActive: boolean;
  canRun: boolean;
  busy: boolean;
  onRunAll: () => void;
  onStop: () => void;
  onStopCheck?: (row: CheckRow) => void;
  onActivity?: (row: CheckRow) => void;
  footer?: ReactNode;
  liveNotes?: Record<string, string>;
  scanActivity?: DataItem[];
  selectedRunEvents?: DataItem[];
  targetValue?: string;
  /** Run-all is unavailable for this target (for example ownership is not proven). */
  runAllDisabledReason?: string;
  /** Run-all is temporarily blocked (for example another check holds the execution slot). */
  runAllBlockedReason?: string;
  recommendedRow?: CheckRow | null;
  onStartRecommended?: (row: CheckRow) => void;
  runSelection?: string[];
  onRunSelectionChange?: (next: string[]) => void;
};

/** Every compatible check for this target, grouped by category, selectable in place. */
export function CheckQueue({
  rows,
  runAllCount = rows.length,
  catalogCount,
  selectedCheckId,
  canSelect,
  onSelect,
  onInspect,
  scan,
  scanActive,
  canRun,
  busy,
  onRunAll,
  onStop,
  onStopCheck,
  onActivity,
  footer,
  liveNotes = {},
  scanActivity = [],
  selectedRunEvents = [],
  targetValue = 'target',
  runAllDisabledReason = '',
  runAllBlockedReason = '',
  recommendedRow = null,
  onStartRecommended,
  runSelection = [],
  onRunSelectionChange,
}: CheckQueueProps) {
  const [filter, setFilter] = useState<QueueFilter>('all');
  const [openCategories, setOpenCategories] = useState<Record<string, boolean>>({});
  const selection = useMemo(() => new Set(runSelection), [runSelection]);
  const counts = useMemo(() => {
    const result: Record<string, number> = { all: rows.length, verdict: 0 };
    for (const row of rows) {
      result[row.status] = (result[row.status] ?? 0) + 1;
      if (row.readinessCapable) result.verdict += 1;
    }
    return result;
  }, [rows]);
  const matchesFilter = (row: CheckRow) => filter === 'all' || (filter === 'verdict' ? row.readinessCapable : row.status === filter);
  const visibleRows = filter === 'all' ? rows : rows.filter((row) => matchesFilter(row) || row.checkId === selectedCheckId);
  const filteredIds = filter === 'all' ? [] : rows.filter(matchesFilter).map((row) => row.checkId);
  const rankedGroups = useMemo(() => groupRowsByCategory(visibleRows), [visibleRows]);
  // While a run is live, results arrive row by row. Keep the order captured when it started so a
  // row never moves under the pointer or keyboard focus; the status-first order returns after.
  const orderRef = useRef<Map<string, number> | null>(null);
  if (!scanActive || !orderRef.current) {
    orderRef.current = new Map(rankedGroups.flatMap((group) => group.rows).map((row, index) => [row.checkId, index]));
  }
  const groups = useMemo(() => {
    if (!scanActive || !orderRef.current) return rankedGroups;
    const order = orderRef.current;
    const rank = (id: string) => order.get(id) ?? Number.MAX_SAFE_INTEGER;
    return rankedGroups.map((group) => ({ ...group, rows: [...group.rows].sort((left, right) => rank(left.checkId) - rank(right.checkId)) }));
  }, [rankedGroups, scanActive]);
  // A category's default open state is captured the first time it renders, so a status change
  // (for example running to passed) never collapses rows the user is reading.
  const defaultsRef = useRef<Record<string, boolean>>({});
  const scanCheckIds = new Set(Array.isArray(scan?.steps) ? (scan.steps as DataItem[]).map((step) => step.check_id) : []);
  const progress = rowProgress(scan ? rows.filter((row) => scanCheckIds.has(row.checkId)) : rows);
  const current = rows.find((row) => row.status === 'running');
  const waiting = rows.find((row) => row.status === 'waiting');
  const scanStatus = typeof scan?.status === 'string' ? scan.status : '';
  const runAllReason = runAllDisabledReason || runAllBlockedReason;
  const canInclude = canSelect && canRun && Boolean(onRunSelectionChange);

  const scanLogEntries = useMemo(() => {
    return scanActive ? buildScanLiveLogs(scan, rows, scanActivity, targetValue) : [];
  }, [scanActive, scan, rows, scanActivity, targetValue]);

  function changeSelection(ids: string[], include: boolean) {
    if (!onRunSelectionChange) return;
    const runnable = new Set(rows.map((row) => row.checkId));
    const next = new Set(runSelection.filter((id) => runnable.has(id)));
    for (const id of ids) {
      if (!runnable.has(id)) continue;
      if (include) next.add(id);
      else next.delete(id);
    }
    onRunSelectionChange([...next].slice(0, MAX_SCAN_CHECKS));
  }

  let liveText = '';
  if (scanActive) {
    liveText = current
      ? `Running ${progress.done + 1} of ${progress.total}: ${current.name}.`
      : waiting
        ? `Paused by a safe-run limit${waiting.eligibleAt ? ` until ${formatDate(waiting.eligibleAt)}` : ''}. It resumes on its own.`
        : `${progress.done} of ${progress.total} checks complete.`;
  } else if (scan) {
    liveText = `Last scan ${humanizeReason(scanStatus).toLowerCase()}${typeof scan.completed_at === 'string' ? ` ${formatDate(scan.completed_at)}` : ''}: ${progress.done} of ${progress.total} checks finished.`;
  }
  const filterLabel = FILTERS.find((entry) => entry.id === filter)?.label ?? '';

  return (
    <section className="td-checks" id="td-all-checks" aria-labelledby="td-checks-title">
      <header className="td-section-head">
        <div>
          <h2 id="td-checks-title">Checks for this target</h2>
          <p>
            {catalogCount != null
              ? `${catalogCount} checks in the catalog. ${rows.length} are runnable on this target, including observation checks.`
              : `${rows.length} checks are runnable on this target, including observation checks.`}
            {' '}Tick checks to run them together, or open one to see what it sends, its last result and its evidence.
          </p>
        </div>
        {canRun ? (
          scanActive ? (
            <Button variant="secondary" onClick={onStop}><Square size={14} aria-hidden="true" />Stop scan</Button>
          ) : (
            <div className="td-run-all">
              <Button
                variant="secondary"
                onClick={onRunAll}
                loading={busy}
                disabled={runAllCount === 0 || Boolean(runAllReason)}
                aria-describedby={runAllReason ? 'td-run-all-reason' : undefined}
              >
                <Play size={15} aria-hidden="true" />Review all {runAllCount}
              </Button>
              {runAllReason ? <span id="td-run-all-reason" className="td-muted td-run-all-reason">{runAllReason}</span> : null}
            </div>
          )
        ) : null}
      </header>
      {scan ? (
        <div className="td-live-console-wrapper">
          <div className="td-run-progress">
            <div className="td-run-progress-head">
              {scanActive ? <Spinner size={15} /> : <CircleCheck size={15} aria-hidden="true" />}
              <span className="td-live-text" role="status" aria-live="polite">{liveText}</span>
              {scanActive ? <Badge tone="warn">Live probe session</Badge> : null}
            </div>
            <Progress value={progress.percent} label="Checks complete" tone={scanActive ? 'warn' : (counts.failed ?? 0) > 0 ? 'danger' : 'success'} />
          </div>
          {scanActive ? (
            <LiveProbeTerminal
              entries={scanLogEntries}
              active
              title="Live scan activity"
              subtitle="Outside-in probe dispatch, TLS negotiation, benign marker evaluation, and edge response taxonomy"
              activeCheckLabel={current?.checkId || (selectedCheckId && rows.some((r) => r.checkId === selectedCheckId) ? selectedCheckId : undefined)}
              requestsSent={current?.requestsSent}
              maxRequests={current?.maxRequests}
              className="td-scan-terminal"
              defaultExpanded
            />
          ) : null}
        </div>
      ) : null}
      {recommendedRow && onStartRecommended && canRun && !scanActive && !runAllBlockedReason ? (
        <div className="td-recommended" role="group" aria-labelledby="td-recommended-title">
          <div className="td-recommended-copy">
            <span className="td-label" id="td-recommended-title">Recommended first check</span>
            <strong>{recommendedRow.name}</strong>
            <span className="td-muted">
              Produces a readiness verdict{recommendedRow.maxRequests !== null ? ` · at most ${recommendedRow.maxRequests} request${recommendedRow.maxRequests === 1 ? '' : 's'}` : ''}
            </span>
          </div>
          <Button
            size="sm"
            aria-label={`Review and start ${recommendedRow.name}`}
            disabled={Boolean(runAllDisabledReason)}
            aria-describedby={runAllDisabledReason ? 'td-run-all-reason' : undefined}
            onClick={() => onStartRecommended(recommendedRow)}
          >
            <Play size={14} aria-hidden="true" />Review and start
          </Button>
        </div>
      ) : null}
      <div className="td-filters" role="group" aria-label="Filter checks by result">
        {FILTERS.filter((entry) => entry.id === 'all' || (counts[entry.id] ?? 0) > 0).map((entry) => (
          <button
            key={entry.id}
            type="button"
            className="td-filter"
            data-filter={entry.id}
            aria-pressed={filter === entry.id}
            onClick={() => setFilter(entry.id)}
          >
            {entry.label}<span className="tabular-nums">{counts[entry.id] ?? 0}</span>
          </button>
        ))}
        {canInclude && filter !== 'all' && filteredIds.length ? (
          <Button size="sm" variant="ghost" className="td-filter-select" onClick={() => changeSelection(filteredIds, true)}>
            Select {filterLabel.toLowerCase()} ({filteredIds.length})
          </Button>
        ) : null}
      </div>
      {groups.map((group) => {
        const Icon = CATEGORY_ICONS[group.category.icon] ?? Shield;
        const holdsSelection = group.rows.some((row) => row.checkId === selectedCheckId);
        const computedDefault = holdsSelection || filter !== 'all' || group.counts.failed > 0 || group.counts.running > 0 || rows.length <= 12;
        if (defaultsRef.current[group.category.id] === undefined || holdsSelection) defaultsRef.current[group.category.id] = defaultsRef.current[group.category.id] || computedDefault;
        const defaultOpen = defaultsRef.current[group.category.id];
        const open = openCategories[group.category.id] ?? defaultOpen;
        return (
          <div key={group.category.id} className="td-cat-shell" data-selectable={canInclude || undefined}>
          {canInclude ? (
            <CategorySelect label={group.category.label} ids={group.rows.map((row) => row.checkId)} selection={selection} disabled={!canInclude} onChange={changeSelection} />
          ) : null}
          <details
            className="td-cat"
            open={open}
            onToggle={(event) => {
              const next = (event.currentTarget as HTMLDetailsElement).open;
              if (next !== open) setOpenCategories((state) => ({ ...state, [group.category.id]: next }));
            }}
          >
            <summary>
              <span className="td-cat-icon"><Icon size={18} aria-hidden="true" /></span>
              <span className="td-cat-title">
                <strong>{group.category.label}</strong>
                <span className="td-muted">{group.rows.length} check{group.rows.length === 1 ? '' : 's'}</span>
              </span>
              <span className="td-cat-tally">
                {group.counts.failed ? <Badge tone="danger">{`${group.counts.failed} gap${group.counts.failed === 1 ? '' : 's'}`}</Badge> : null}
                {group.counts.passed ? <Badge tone="success">{`${group.counts.passed} protected`}</Badge> : null}
                {group.counts.inconclusive ? <Badge tone="muted">{`${group.counts.inconclusive} inconclusive`}</Badge> : null}
                {group.counts.not_run ? <Badge tone="muted">{`${group.counts.not_run} not run`}</Badge> : null}
                {group.counts.running ? <Badge tone="warn">Running</Badge> : null}
              </span>
              <ChevronRight size={16} className="td-chevron" aria-hidden="true" />
            </summary>
            <ul className="td-check-list">
              {group.rows.map((row) => (
                <CheckQueueRow
                  key={row.checkId}
                  row={row}
                  selected={row.checkId === selectedCheckId}
                  onSelect={onSelect}
                  included={selection.has(row.checkId)}
                  canInclude={canInclude}
                  onToggleInclude={canInclude ? (checkId) => changeSelection([checkId], !selection.has(checkId)) : undefined}
                  onInspect={onInspect}
                  onStopCheck={onStopCheck}
                  onActivity={onActivity}
                  liveNote={liveNotes[row.checkId]}
                  targetValue={targetValue}
                  runEvents={row.checkId === selectedCheckId ? selectedRunEvents : undefined}
                />
              ))}
            </ul>
          </details>
          </div>
        );
      })}
      {!groups.length ? (
        <p className="td-muted">
          No checks match this filter. <button type="button" className="td-inline-link" onClick={() => setFilter('all')}>Show all checks</button>
        </p>
      ) : null}
      {footer}
    </section>
  );
}
