import { useMemo, useState, type ReactNode } from 'react';
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
  Clock,
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
  ShieldAlert,
  ShieldCheck,
  ShieldQuestion,
  ShieldX,
  Square,
  Waves,
  Waypoints,
  Workflow,
  type LucideIcon,
} from 'lucide-react';
import type { DataItem } from '../../lib/types';
import { formatDate } from '../../lib/utils';
import { buildDetailHref } from '../../lib/route-params';
import { plainVerdictLabel } from '../../lib/plain-language.mjs';
import { formatStepRequest, formatStepResponse, humanizeReason } from '../../lib/validation-scan.mjs';
import {
  efficacySentence,
  edgeEvidenceSignals,
  groupRowsByCategory,
  providerName,
  providerLogoId,
  rowProgress,
  type CategoryIcon,
  type CheckRow,
  type EdgePhase,
  type LayerEfficacy,
  type RowStatus,
} from '../../lib/domain-checks.mjs';
import { Badge } from '../ui/badge';
import { AnchorButton, Button } from '../ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../ui/card';
import { Progress } from '../ui/progress';
import { ProviderLogo } from '../integrations/provider-logos';

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

const EFFICACY_ICONS: Record<string, LucideIcon> = {
  protecting: ShieldCheck,
  partial: ShieldAlert,
  mostly_exposed: ShieldX,
  not_protecting: ShieldX,
  bypassable: ShieldX,
  present_unmeasured: Shield,
  absent: ShieldQuestion,
  unknown: ShieldQuestion,
};

const TIER_COPY: Record<string, string> = {
  E2: 'Connection observed',
  E3: 'Behavior observed',
};

const FILTERS: Array<{ id: 'all' | RowStatus; label: string }> = [
  { id: 'all', label: 'All' },
  { id: 'failed', label: 'Exposed' },
  { id: 'passed', label: 'Protected' },
  { id: 'inconclusive', label: 'Inconclusive' },
  { id: 'observed', label: 'Observed' },
  { id: 'running', label: 'Running' },
  { id: 'waiting', label: 'Waiting' },
  { id: 'queued', label: 'Queued' },
  { id: 'blocked', label: 'Safety gate' },
  { id: 'not_run', label: 'Not run' },
];

function asItem(value: unknown): DataItem | null {
  return value && typeof value === 'object' && !Array.isArray(value) ? value as DataItem : null;
}

function str(item: DataItem | null | undefined, key: string) {
  const value = item?.[key];
  return value === undefined || value === null ? '' : String(value);
}

/** Inline spinner for "work in flight"; reduced motion keeps it static. */
function Spinner({ size = 16 }: { size?: number }) {
  return <LoaderCircle size={size} className="td-spin" aria-hidden="true" />;
}

const PHASE_BADGE: Record<string, { label: string; tone: 'success' | 'warn' | 'danger' | 'info' | 'muted' }> = {
  detected: { label: 'Edge detected', tone: 'success' },
  not_detected: { label: 'No edge detected', tone: 'warn' },
  inconclusive: { label: 'Inconclusive', tone: 'warn' },
  error: { label: 'Detection failed', tone: 'danger' },
  evaluating: { label: 'Evaluating', tone: 'info' },
  pending: { label: 'Evaluating', tone: 'info' },
  locked: { label: 'Waiting for ownership', tone: 'muted' },
  waiting: { label: 'Queued', tone: 'muted' },
  no_result: { label: 'No usable result', tone: 'warn' },
  not_started: { label: 'Not started', tone: 'muted' },
};

function phaseIsEvaluating(phase: EdgePhase) {
  return phase === 'evaluating' || phase === 'pending';
}

function familyDetectionLine(edge: DataItem | null, family: 'waf' | 'cdn', phase: EdgePhase) {
  if (phaseIsEvaluating(phase)) return null;
  const row = asItem(edge?.[family]);
  const status = str(row, 'status');
  const provider = str(row, 'vendor') || str(row, 'provider');
  if (status === 'detected') return { tone: 'success' as const, text: provider ? `Detected · ${providerName(provider)}` : 'Detected', provider };
  if (status === 'not_detected') return { tone: 'warn' as const, text: 'Not detected', provider: '' };
  if (edge) return { tone: 'muted' as const, text: 'Inconclusive', provider: '' };
  return null;
}

function EfficacyMeter({ efficacy }: { efficacy: LayerEfficacy }) {
  const total = efficacy.passed + efficacy.failed + efficacy.inconclusive;
  if (!total) return <div className="td-meter td-meter-empty" aria-hidden="true" />;
  const label = `${efficacy.passed} blocked, ${efficacy.failed} reached the application, ${efficacy.inconclusive} inconclusive`;
  return (
    <div className="td-meter" role="img" aria-label={label}>
      {efficacy.passed ? <span className="td-meter-seg" data-tone="success" style={{ flexGrow: efficacy.passed }} /> : null}
      {efficacy.failed ? <span className="td-meter-seg" data-tone="danger" style={{ flexGrow: efficacy.failed }} /> : null}
      {efficacy.inconclusive ? <span className="td-meter-seg" data-tone="muted" style={{ flexGrow: efficacy.inconclusive }} /> : null}
    </div>
  );
}

function LayerTile({
  family,
  title,
  edge,
  phase,
  efficacy,
}: {
  family: 'waf' | 'cdn';
  title: string;
  edge: DataItem | null;
  phase: EdgePhase;
  efficacy: LayerEfficacy;
}) {
  const detection = familyDetectionLine(edge, family, phase);
  const logo = detection?.provider ? providerLogoId(detection.provider) : '';
  const VerdictIcon = EFFICACY_ICONS[efficacy.status] ?? ShieldQuestion;
  const FallbackIcon = family === 'waf' ? ShieldCheck : Globe;
  const evaluating = phaseIsEvaluating(phase);
  return (
    <section className="td-shield" data-tone={efficacy.tone} aria-label={`${title}: ${evaluating ? 'evaluating' : efficacy.label}`}>
      <header className="td-shield-head">
        <span className="td-shield-mark" data-provider={logo || undefined}>
          {logo ? <ProviderLogo provider={logo} size={22} /> : <FallbackIcon size={20} aria-hidden="true" />}
        </span>
        <span className="td-shield-title">
          <span className="td-kicker">{family === 'waf' ? 'WAF' : 'CDN'}</span>
          <strong>{title}</strong>
        </span>
      </header>
      <div className="td-shield-detect">
        {evaluating ? (
          <span className="td-evaluating"><Spinner />Evaluating with live fingerprint probes</span>
        ) : detection ? (
          <Badge tone={detection.tone}>{detection.text}</Badge>
        ) : (
          <span className="muted small">Not evaluated yet</span>
        )}
      </div>
      <div className="td-shield-efficacy">
        <span className="td-kicker">Efficacy</span>
        <span className="td-shield-verdict" data-tone={efficacy.tone}>
          <VerdictIcon size={18} aria-hidden="true" />
          {efficacy.label}
          {efficacy.score !== null ? <span className="td-shield-score tabular-nums">{`${efficacy.score}%`}</span> : null}
        </span>
        <EfficacyMeter efficacy={efficacy} />
        <p>{efficacySentence(efficacy)}</p>
        {efficacy.exposedChecks.length ? (
          <p className="td-shield-gaps">
            Reached your application: {efficacy.exposedChecks.slice(0, 3).join(', ')}
            {efficacy.exposedChecks.length > 3 ? ` and ${efficacy.exposedChecks.length - 3} more` : ''}.
          </p>
        ) : null}
      </div>
    </section>
  );
}

function EvidenceDisclosure({ edge }: { edge: DataItem | null }) {
  const { layers, facts } = useMemo(() => edgeEvidenceSignals(edge), [edge]);
  if (!edge || (!layers.length && !facts.length)) return null;
  const observedAt = str(edge, 'observed_at');
  return (
    <details className="td-evidence">
      <summary>
        <Fingerprint size={16} aria-hidden="true" />
        <span>How we found out</span>
        <span className="muted small">{layers.length} layer{layers.length === 1 ? '' : 's'} · {facts.length} recorded fact{facts.length === 1 ? '' : 's'}</span>
        <ChevronRight size={16} className="td-chevron" aria-hidden="true" />
      </summary>
      <div className="td-evidence-body">
        {layers.length ? (
          <ul className="td-evidence-layers">
            {layers.map((layer) => (
              <li key={`${layer.family}-${layer.provider}`} className="td-evidence-layer">
                <div className="td-evidence-layer-head">
                  <span className="td-shield-mark" data-provider={layer.logo || undefined}>
                    {layer.logo ? <ProviderLogo provider={layer.logo} size={18} /> : <Shield size={16} aria-hidden="true" />}
                  </span>
                  <strong>{layer.name}</strong>
                  <Badge tone="muted" mono>{layer.family.toUpperCase()}</Badge>
                  {layer.confidence !== null ? <span className="muted small tabular-nums">{`${layer.confidence}% confidence`}</span> : null}
                  {layer.conflicting ? <Badge tone="warn">Signals conflict</Badge> : layer.agreement === 'agreement' ? <Badge tone="success">Sources agree</Badge> : null}
                </div>
                <ul className="td-evidence-sources">
                  {layer.sources.map((source) => (
                    <li key={source.id}>
                      <span className="td-evidence-method">{source.method}</span>
                      <span className="muted">{source.detail}</span>
                    </li>
                  ))}
                </ul>
                {layer.signals.length ? (
                  <p className="td-evidence-signals">
                    <span className="muted">Matched signals</span>
                    {layer.signals.map((signal) => <code key={signal}>{signal}</code>)}
                  </p>
                ) : null}
              </li>
            ))}
          </ul>
        ) : null}
        {facts.length ? (
          <dl className="td-evidence-facts">
            {facts.map((fact) => (
              <div key={fact.id}>
                <dt>{fact.label}</dt>
                <dd className={fact.id === 'cname' || fact.id === 'ips' ? 'mono' : undefined}>{fact.value}</dd>
              </div>
            ))}
          </dl>
        ) : null}
        <p className="muted small">
          {observedAt ? `Observed ${formatDate(observedAt)} by a signed external probe. ` : ''}
          Detection proves a layer is present; efficacy comes from whether the checks below were blocked.
        </p>
      </div>
    </details>
  );
}

export type EdgeProtectionCardProps = {
  edge: DataItem | null;
  phase: EdgePhase;
  phaseDetail?: string;
  waf: LayerEfficacy;
  cdn: LayerEfficacy;
  originExposed: boolean;
  action?: ReactNode;
};

/** Hero card: what sits in front of the domain, how we know, and whether it actually protects. */
export function EdgeProtectionCard({ edge, phase, phaseDetail, waf, cdn, originExposed, action }: EdgeProtectionCardProps) {
  const badge = PHASE_BADGE[phase] ?? PHASE_BADGE.inconclusive;
  const evaluating = phaseIsEvaluating(phase);
  return (
    <Card className="td-edge-hero" aria-busy={evaluating || undefined}>
      <CardHeader>
        <div>
          <CardTitle>Edge protection</CardTitle>
          <CardDescription>The WAF and CDN in front of this domain, the evidence that found them, and whether your check results show them actually blocking attacks.</CardDescription>
        </div>
        <Badge tone={badge.tone}>
          {evaluating ? <span className="scan-live-dot" aria-hidden="true" /> : null}
          {badge.label}
        </Badge>
      </CardHeader>
      <CardContent className="td-edge-hero-body">
        <div className="td-live" role="status" aria-live="polite">
          {evaluating ? 'Evaluating the WAF and CDN in front of this domain.' : ''}
        </div>
        {phaseDetail ? (
          <div className="td-edge-callout" data-phase={phase}>
            {phase === 'locked' ? <Lock size={16} aria-hidden="true" /> : <Clock size={16} aria-hidden="true" />}
            <p>{phaseDetail}</p>
            {action}
          </div>
        ) : null}
        <div className="td-shield-grid">
          <LayerTile family="waf" title="Web application firewall" edge={edge} phase={phase} efficacy={waf} />
          <LayerTile family="cdn" title="CDN and edge network" edge={edge} phase={phase} efficacy={cdn} />
        </div>
        {originExposed ? (
          <div className="td-origin-alert" role="note">
            <Server size={16} aria-hidden="true" />
            <p><strong>Origin reachable directly.</strong> Traffic can go around both the WAF and the CDN. Lock the origin down to edge addresses only.</p>
          </div>
        ) : null}
        <EvidenceDisclosure edge={edge} />
      </CardContent>
    </Card>
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
  if (row.status === 'running') return 'Probe in flight. The result appears here as soon as the signed worker reports.';
  if (row.status === 'queued') return 'Queued. Checks run one at a time.';
  if (row.status === 'not_run') return 'Not run on this domain yet.';
  if (row.status === 'skipped' || row.status === 'cancelled') return row.reason ? humanizeReason(row.reason) : `${row.label}.`;
  if (row.status === 'observed') return row.explanation || 'Recorded transport behavior. Transport-only checks inform the picture but never decide protection.';
  return row.explanation || (row.verdict ? plainVerdictLabel(row.verdict) : row.label);
}

function CheckRowItem({ row }: { row: CheckRow }) {
  const StatusIcon = STATUS_ICONS[row.status] ?? CircleDashed;
  const sent = rowSentLine(row);
  return (
    <li className="td-check" data-status={row.status}>
      <details>
        <summary>
          <span className="td-check-icon" data-tone={row.tone}>
            <StatusIcon size={16} className={row.status === 'running' ? 'td-spin' : undefined} aria-hidden="true" />
          </span>
          <span className="td-check-name">
            <strong>{row.name}</strong>
            <code>{row.checkId}</code>
          </span>
          {TIER_COPY[row.tier] ? <span className="td-check-tier">{TIER_COPY[row.tier]}</span> : null}
          <Badge tone={row.tone}>{row.label}</Badge>
          <ChevronRight size={16} className="td-chevron" aria-hidden="true" />
        </summary>
        <dl className="td-check-detail">
          <div><dt>How it works</dt><dd>{row.description || row.category.how}</dd></div>
          {row.verdictLogic ? <div><dt>How it decides</dt><dd>{row.verdictLogic}</dd></div> : null}
          <div><dt>What it sends</dt><dd>{rowRequestLine(row)}</dd></div>
          {sent ? <div><dt>Requests sent</dt><dd className="tabular-nums">{sent}</dd></div> : null}
          {row.response ? <div><dt>Response</dt><dd>{formatStepResponse(row.response)}</dd></div> : null}
          <div><dt>Result</dt><dd>{rowResultLine(row)}</dd></div>
          {row.finishedAt || row.startedAt ? <div><dt>{row.finishedAt ? 'Finished' : 'Started'}</dt><dd>{formatDate(row.finishedAt || row.startedAt)}</dd></div> : null}
        </dl>
        {row.runId ? (
          <div className="td-check-links">
            <AnchorButton size="sm" variant="ghost" href={buildDetailHref('run-detail', row.runId)}>Open run evidence</AnchorButton>
          </div>
        ) : null}
      </details>
    </li>
  );
}

export type AllChecksPanelProps = {
  rows: CheckRow[];
  declarationOnlyCount: number;
  scan: DataItem | null;
  scanActive: boolean;
  canRun: boolean;
  runDisabledReason: string;
  busy: boolean;
  onRunAll: () => void;
  onStop: () => void;
};

/** Every run-all check for this domain, grouped by category, with live status and what it did. */
export function AllChecksPanel({ rows, declarationOnlyCount, scan, scanActive, canRun, runDisabledReason, busy, onRunAll, onStop }: AllChecksPanelProps) {
  const [filter, setFilter] = useState<'all' | RowStatus>('all');
  const [openCategories, setOpenCategories] = useState<Record<string, boolean>>({});
  const counts = useMemo(() => {
    const result: Record<string, number> = { all: rows.length };
    for (const row of rows) result[row.status] = (result[row.status] ?? 0) + 1;
    return result;
  }, [rows]);
  const visibleRows = filter === 'all' ? rows : rows.filter((row) => row.status === filter);
  const groups = useMemo(() => groupRowsByCategory(visibleRows), [visibleRows]);
  const progress = rowProgress(rows);
  const current = rows.find((row) => row.status === 'running');
  const waiting = rows.find((row) => row.status === 'waiting');
  const scanId = str(scan, 'id');
  const scanStatus = str(scan, 'status');

  let liveText = '';
  if (scanActive) {
    liveText = current
      ? `Running ${progress.done + 1} of ${progress.total}: ${current.name}.`
      : waiting
        ? `Paused by a safe-run limit${waiting.eligibleAt ? ` until ${formatDate(waiting.eligibleAt)}` : ''}. It resumes on its own.`
        : `${progress.done} of ${progress.total} checks complete.`;
  } else if (scan) {
    liveText = `Last run ${humanizeReason(scanStatus).toLowerCase()}${str(scan, 'completed_at') ? ` ${formatDate(str(scan, 'completed_at'))}` : ''}: ${progress.done} of ${progress.total} checks finished.`;
  }

  return (
    <Card className="td-checks" id="td-all-checks">
      <CardHeader>
        <div>
          <CardTitle>All checks</CardTitle>
          <CardDescription>
            {rows.length} bounded external checks apply to this domain. Open any check to see how it works, what it sent, and what came back.
          </CardDescription>
        </div>
        {canRun ? (
          scanActive ? (
            <Button variant="secondary" onClick={onStop}><Square size={14} aria-hidden="true" />Stop run</Button>
          ) : (
            <Button onClick={onRunAll} disabled={Boolean(runDisabledReason) || busy} loading={busy} title={runDisabledReason || undefined}>
              <Play size={15} aria-hidden="true" />Run all checks
            </Button>
          )
        ) : null}
      </CardHeader>
      <CardContent className="td-checks-body">
        {scan ? (
          <div className="td-run-progress">
            <div className="td-run-progress-head">
              {scanActive ? <Spinner size={15} /> : <CircleCheck size={15} aria-hidden="true" />}
              <span className="td-live-text" role="status" aria-live="polite">{liveText}</span>
              {scanId ? <a className="scan-link small" href={buildDetailHref('scan-detail', scanId)}>Full activity log</a> : null}
            </div>
            <Progress value={progress.percent} label="Checks complete" tone={scanActive ? 'accent' : (counts.failed ?? 0) > 0 ? 'danger' : 'success'} />
          </div>
        ) : null}
        {canRun && runDisabledReason && !scanActive ? <p className="muted small">{runDisabledReason}</p> : null}
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
          const defaultOpen = filter !== 'all' || group.counts.failed > 0 || group.counts.running > 0 || rows.length <= 12;
          const open = openCategories[group.category.id] ?? defaultOpen;
          return (
            <details
              key={group.category.id}
              className="td-cat"
              open={open}
              onToggle={(event) => {
                const next = (event.currentTarget as HTMLDetailsElement).open;
                if (next !== open) setOpenCategories((current) => ({ ...current, [group.category.id]: next }));
              }}
            >
              <summary>
                <span className="td-cat-icon"><Icon size={18} aria-hidden="true" /></span>
                <span className="td-cat-title">
                  <strong>{group.category.label}</strong>
                  <span className="muted small">{group.rows.length} check{group.rows.length === 1 ? '' : 's'}</span>
                </span>
                <span className="td-cat-tally">
                  {group.counts.failed ? <Badge tone="danger">{`${group.counts.failed} exposed`}</Badge> : null}
                  {group.counts.passed ? <Badge tone="success">{`${group.counts.passed} protected`}</Badge> : null}
                  {group.counts.running ? <Badge tone="info">Running</Badge> : null}
                </span>
                <ChevronRight size={16} className="td-chevron" aria-hidden="true" />
              </summary>
              <p className="td-cat-how">{group.category.how}</p>
              <ul className="td-check-list">
                {group.rows.map((row) => <CheckRowItem key={row.checkId} row={row} />)}
              </ul>
            </details>
          );
        })}
        {!groups.length ? <p className="muted">No checks match this filter.</p> : null}
        {declarationOnlyCount > 0 ? (
          <p className="muted small td-decl-note">
            {declarationOnlyCount} declaration-only checks also apply. They record customer-declared readiness, send no traffic, and are not part of Run all checks.
          </p>
        ) : null}
      </CardContent>
    </Card>
  );
}
