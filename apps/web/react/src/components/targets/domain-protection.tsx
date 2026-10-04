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
  groupRowsByCategory,
  rowProgress,
  type CategoryIcon,
  type CheckRow,
  type MarkerEffectiveness,
  type ProviderFamilyRow,
  type RowStatus,
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

const FILTERS: Array<{ id: 'all' | RowStatus; label: string }> = [
  { id: 'all', label: 'All' },
  { id: 'failed', label: 'Gap found' },
  { id: 'passed', label: 'Passed' },
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
  reachable: { label: 'Directly reachable', tone: 'danger', detail: 'A declared origin answered directly, so traffic can bypass the edge.' },
  exposed: { label: 'Directly reachable', tone: 'danger', detail: 'A declared origin answered directly, so traffic can bypass the edge.' },
  not_reachable: { label: 'Not reachable in this observation', tone: 'success', detail: 'The declared origin did not answer direct requests during the recorded check.' },
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
};

/** Flat, ruled list: one row per family, each from its own recorded source only. */
export function ProviderObservations({ rows, effectiveness, originStatus, originDetail, evaluating, note, action, onInspect }: ProviderObservationsProps) {
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
        {effectiveness ? (
          <p>
            <strong className="tabular-nums">{effectiveness.blocked}</strong> blocked ·{' '}
            <strong className="tabular-nums">{effectiveness.allowed}</strong> allowed ·{' '}
            <span className="tabular-nums">{effectiveness.inconclusive}</span> inconclusive
            {effectiveness.percentage !== null
              ? <> · <span className="tabular-nums">{effectiveness.percentage}%</span> of definitive markers</>
              : <> · no definitive markers, so no percentage</>}
          </p>
        ) : (
          <p className="td-muted">Not measured. Detection alone does not show whether anything is blocked.</p>
        )}
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
  canSelect,
  onSelect,
  onInspect,
  onStopCheck,
  onActivity,
  liveNote,
  targetValue,
  runEvents,
}: {
  row: CheckRow;
  selected: boolean;
  canSelect: boolean;
  onSelect: (checkId: string) => void;
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
  return (
    <li className="td-check" data-status={row.status} data-selected={selected || undefined} data-focus-key={`check-${row.checkId}`}>
      <div className="td-check-row">
        <label className="td-check-choice">
          <input
            type="radio"
            name="target-run-check"
            value={row.checkId}
            checked={selected}
            disabled={!canSelect}
            onChange={() => onSelect(row.checkId)}
            aria-label={`Select ${row.name}`}
          />
        </label>
        <button type="button" className="td-check-summary" aria-expanded={selected} onClick={() => onSelect(row.checkId)}>
          <span className="td-check-icon" data-tone={row.tone}>
            <StatusIcon size={16} className={row.status === 'running' ? 'td-spin' : undefined} aria-hidden="true" />
          </span>
          <span className="td-check-name">
            <strong>{row.name}</strong>
            <code>{row.checkId}</code>
          </span>
          {TIER_COPY[row.tier] ? <span className="td-check-tier">{TIER_COPY[row.tier]}</span> : null}
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
                    <span className="td-muted"> · Probes in flight ({row.requestsSent ?? 13}/{row.maxRequests ?? 16} sent)</span>
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

export type CheckQueueProps = {
  rows: CheckRow[];
  selectedCheckId: string;
  canSelect: boolean;
  onSelect: (checkId: string) => void;
  onInspect: (row: CheckRow) => void;
  scan: DataItem | null;
  scanActive: boolean;
  canRun: boolean;
  runDisabledReason: string;
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
};

/** Every compatible check for this target, grouped by category, selectable in place. */
export function CheckQueue({
  rows,
  selectedCheckId,
  canSelect,
  onSelect,
  onInspect,
  scan,
  scanActive,
  canRun,
  runDisabledReason,
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
}: CheckQueueProps) {
  const [filter, setFilter] = useState<'all' | RowStatus>('all');
  const [openCategories, setOpenCategories] = useState<Record<string, boolean>>({});
  const counts = useMemo(() => {
    const result: Record<string, number> = { all: rows.length };
    for (const row of rows) result[row.status] = (result[row.status] ?? 0) + 1;
    return result;
  }, [rows]);
  const visibleRows = filter === 'all' ? rows : rows.filter((row) => row.status === filter || row.checkId === selectedCheckId);
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
  const progress = rowProgress(rows);
  const current = rows.find((row) => row.status === 'running');
  const waiting = rows.find((row) => row.status === 'waiting');
  const scanStatus = typeof scan?.status === 'string' ? scan.status : '';

  const scanLogEntries = useMemo(() => {
    return buildScanLiveLogs(scan, rows, scanActivity, targetValue);
  }, [scan, rows, scanActivity, targetValue]);

  let liveText = '';
  if (scanActive) {
    liveText = current
      ? `Running ${progress.done + 1} of ${progress.total}: ${current.name}.`
      : waiting
        ? `Paused by a safe-run limit${waiting.eligibleAt ? ` until ${formatDate(waiting.eligibleAt)}` : ''}. It resumes on its own.`
        : `${progress.done} of ${progress.total} checks complete.`;
  } else if (scan) {
    liveText = `Last multi-check run ${humanizeReason(scanStatus).toLowerCase()}${typeof scan.completed_at === 'string' ? ` ${formatDate(scan.completed_at)}` : ''}: ${progress.done} of ${progress.total} checks finished.`;
  }

  return (
    <section className="td-checks" id="td-all-checks" aria-labelledby="td-checks-title">
      <header className="td-section-head">
        <div>
          <h2 id="td-checks-title">Checks for this target</h2>
          <p>{rows.length} bounded external checks are compatible with this target kind. Select one to see what it sends, its last result and its evidence.</p>
        </div>
        {canRun ? (
          scanActive ? (
            <Button variant="secondary" onClick={onStop}><Square size={14} aria-hidden="true" />Stop run</Button>
          ) : (
            <Button variant="secondary" onClick={onRunAll} disabled={Boolean(runDisabledReason) || busy} loading={busy} title={runDisabledReason || undefined}>
              <Play size={15} aria-hidden="true" />Review all {rows.length}
            </Button>
          )
        ) : null}
      </header>
      {scan || current || (selectedCheckId && rows.some((r) => r.checkId === selectedCheckId && r.status === 'running')) ? (
        <div className="td-live-console-wrapper">
          <div className="td-run-progress">
            <div className="td-run-progress-head">
              {scanActive ? <Spinner size={15} /> : <CircleCheck size={15} aria-hidden="true" />}
              <span className="td-live-text" role="status" aria-live="polite">{liveText}</span>
              {scanActive ? <Badge tone="info">Live probe session</Badge> : null}
            </div>
            <Progress value={progress.percent} label="Checks complete" tone={scanActive ? 'accent' : (counts.failed ?? 0) > 0 ? 'danger' : 'success'} />
          </div>
          <LiveProbeTerminal
            entries={scanLogEntries}
            active={scanActive || current?.status === 'running'}
            title={scanActive ? 'Live Run Activity Stream' : 'Run Execution Logs'}
            subtitle="Outside-in probe dispatch, TLS negotiation, benign marker evaluation, and edge response taxonomy"
            activeCheckLabel={current?.checkId || (selectedCheckId && rows.some((r) => r.checkId === selectedCheckId) ? selectedCheckId : undefined)}
            requestsSent={current?.requestsSent}
            maxRequests={current?.maxRequests}
            className="td-scan-terminal"
            defaultExpanded={false}
          />
        </div>
      ) : null}
      {canRun && runDisabledReason && !scanActive ? <p className="td-muted">{runDisabledReason}</p> : null}
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
      </div>
      {groups.map((group) => {
        const Icon = CATEGORY_ICONS[group.category.icon] ?? Shield;
        const holdsSelection = group.rows.some((row) => row.checkId === selectedCheckId);
        const computedDefault = holdsSelection || filter !== 'all' || group.counts.failed > 0 || group.counts.running > 0 || rows.length <= 12;
        if (defaultsRef.current[group.category.id] === undefined || holdsSelection) defaultsRef.current[group.category.id] = defaultsRef.current[group.category.id] || computedDefault;
        const defaultOpen = defaultsRef.current[group.category.id];
        const open = openCategories[group.category.id] ?? defaultOpen;
        return (
          <details
            key={group.category.id}
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
                {group.counts.passed ? <Badge tone="success">{`${group.counts.passed} passed`}</Badge> : null}
                {group.counts.running ? <Badge tone="info">Running</Badge> : null}
              </span>
              <ChevronRight size={16} className="td-chevron" aria-hidden="true" />
            </summary>
            <ul className="td-check-list">
              {group.rows.map((row) => (
                <CheckQueueRow
                  key={row.checkId}
                  row={row}
                  selected={row.checkId === selectedCheckId}
                  canSelect={canSelect}
                  onSelect={onSelect}
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
