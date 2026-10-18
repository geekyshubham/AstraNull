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
  CircleSlash,
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
import { plainVerdictLabel, plainVerdictShortLabel } from '../../lib/plain-language.mjs';
import { verdictTone } from '../../lib/status-tone';
import { buildDetailHref } from '../../lib/route-params';
import { formatStepRequest, formatStepResponse, humanizeReason } from '../../lib/validation-scan.mjs';
import {
  MAX_SCAN_CHECKS,
} from '../../lib/validation-scan.mjs';
import {
  ROW_STATUS_META,
  efficacySentence,
  groupRowsByCategory,
  rowProgress,
  wafRuleSentences,
  type CategoryIcon,
  type CustomCanaryMember,
  type CheckRow,
  type EdgeEfficacy,
  type MarkerEffectiveness,
  type ProviderFamilyRow,
  type RowStatus,
  type WafRuleEnforcement,
} from '../../lib/domain-checks.mjs';
import { DECLARATION_KEYS, controlsHref, prerequisiteCta, prerequisiteSection, prerequisiteTone, type CheckPrerequisite } from '../../lib/control-declarations.mjs';
import { buildScanLiveLogs } from '../../lib/live-probe-logs';
import { UnifiedActivityLog, type ActivityMarker } from '../activity/unified-activity-log';
import { Badge } from '../ui/badge';
import { NotTestedNote } from '../runs/not-tested-note';
import { AnchorButton, Button } from '../ui/button';
import { CheckClassChips, CheckClassLegend, CheckImpactBadge, CheckImpactIcon } from '../checks/check-class-chips';
import { CHECK_IMPACT_CLASSES, classifyCheck, classifyCheckImpact, type CheckImpactId } from '../../lib/check-classification.mjs';
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
  not_tested: CircleSlash,
  observed: Eye,
  retained: Hourglass,
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
type ImpactFilter = 'all' | CheckImpactId;

const IMPACT_FILTERS: Array<{ id: ImpactFilter; label: string }> = [
  { id: 'all', label: 'All' },
  { id: 'non_invasive', label: CHECK_IMPACT_CLASSES.non_invasive.label },
  { id: 'invasive', label: CHECK_IMPACT_CLASSES.invasive.label },
];

const FILTERS: Array<{ id: QueueFilter; label: string }> = [
  { id: 'all', label: 'All' },
  { id: 'verdict', label: 'Produces a verdict' },
  { id: 'failed', label: ROW_STATUS_META.failed.label },
  { id: 'passed', label: ROW_STATUS_META.passed.label },
  { id: 'inconclusive', label: 'Inconclusive' },
  { id: 'not_tested', label: ROW_STATUS_META.not_tested.label },
  { id: 'observed', label: 'Observed' },
  { id: 'retained', label: 'Retained, not current' },
  { id: 'running', label: 'Running' },
  { id: 'waiting', label: 'Waiting' },
  { id: 'queued', label: 'Queued' },
  { id: 'blocked', label: 'Safety gate' },
  { id: 'not_run', label: 'Not run' },
];


function Spinner({ size = 16 }: { size?: number }) {
  return <LoaderCircle size={size} className="td-spin" aria-hidden="true" />;
}

export type ProviderObservationsProps = {
  rows: ProviderFamilyRow[];
  effectiveness: MarkerEffectiveness | null;
  evaluating: boolean;
  note?: ReactNode;
  action?: ReactNode;
  onInspect: (row: ProviderFamilyRow) => void;
  /** WAF and edge efficacy from fresh, current-version verdicts. */
  efficacy?: EdgeEfficacy | null;
  /** Managed-rule versus custom-canary enforcement, rolled up by distinct rule; null when nothing is recorded. */
  wafRules?: WafRuleEnforcement | null;
  /** Custom canary rules the server rolled up, each linked to the run it graded. */
  canaryMembers?: CustomCanaryMember[];
  checkName?: (checkId: string) => string;
  onOpenChecks?: () => void;
};

/** Flat, ruled list: one row per family, each from its own recorded source only. */
export function ProviderObservations({ rows, effectiveness, evaluating, note, action, onInspect, efficacy = null, wafRules = null, canaryMembers = [], checkName, onOpenChecks }: ProviderObservationsProps) {
  const ruleLines = wafRuleSentences(wafRules);
  const edgeProxyRow = rows.find(
    (r) => (r.family === 'cdn' || r.family === 'waf') && r.status === 'detected'
  );
  const hasEdgeProxy = Boolean(edgeProxyRow);
  const detectedProxyName = edgeProxyRow?.providerName || 'an edge provider';

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
          const statusLabel = row.statusLabel;
          let metaText = '';

          if (hasEdgeProxy && row.family === 'cloud' && (row.status === 'not_detected' || row.status === 'not_recorded')) {
            metaText = `An edge fingerprint for ${detectedProxyName} does not establish the cloud hosting provider.`;
          } else if (hasEdgeProxy && row.family === 'origin_hosting' && (row.status === 'unknown' || row.status === 'not_recorded')) {
            metaText = `An edge fingerprint for ${detectedProxyName} does not establish origin hosting, reachability, or lockdown. Declare an origin under Origin Relations to test.`;
          } else if (row.family === 'dns' && (row.status === 'unknown' || row.status === 'not_recorded')) {
            metaText = 'The edge scan does not look up authoritative nameservers, so the DNS provider is not recorded yet.';
          } else if (row.observedAt || row.sources.length || row.status === 'detected') {
            const timeText = row.observedAt ? `Observed ${formatDate(row.observedAt)}` : 'Observation time not recorded';
            const sourceText = row.sources.length
              ? ` · ${row.sources.map((source) => source.method).join(', ')}`
              : row.status === 'detected'
                ? ' · Source not recorded'
                : '';
            metaText = `${timeText}${sourceText}`;
          }
          const describedBy = `td-provider-${row.family}-value${metaText ? ` td-provider-${row.family}-meta` : ''}`;

          return (
            <li key={row.family} className="td-provider-row" data-status={row.status}>
              <button
                type="button"
                className="td-provider-tile"
                data-focus-key={`provider-${row.family}`}
                aria-label={`How ${row.title} was identified`}
                aria-describedby={describedBy}
                onClick={() => onInspect(row)}
              >
                <span className="td-provider-top">
                  <span className="td-provider-mark" aria-hidden="true">
                    {row.logo ? <ProviderLogo provider={row.logo as ProviderLogoId} size={18} /> : <Shield size={16} />}
                  </span>
                  <span className="td-provider-title">{row.title}</span>
                  <Fingerprint size={14} className="td-provider-inspect" aria-hidden="true" />
                </span>
                <span className="td-provider-value" id={`td-provider-${row.family}-value`}>
                  {evaluating && row.source === 'none' && (row.family === 'waf' || row.family === 'cdn') ? (
                    <span className="td-evaluating"><Spinner size={14} />Detection running</span>
                  ) : (
                    <>
                      {row.providerName ? <strong>{row.providerName}</strong> : null}
                      <Badge tone={row.tone}>{statusLabel}</Badge>
                      {row.freshness === 'stale' ? <span className="td-provider-stale">Stale</span> : null}
                    </>
                  )}
                </span>
                {metaText ? <span className="td-provider-meta" id={`td-provider-${row.family}-meta`}>{metaText}</span> : null}
              </button>
            </li>
          );
        })}
      </ul>
      <div className="td-efficacy" role="group" aria-labelledby="td-efficacy-title">
        <div className="td-efficacy-head">
          <h3 id="td-efficacy-title">Is it working?</h3>
          {onOpenChecks ? <Button size="sm" variant="ghost" onClick={onOpenChecks}>Review checks</Button> : null}
        </div>
        {!effectiveness && !wafRules && (!efficacy || ['unknown', 'absent', 'present_unmeasured'].includes(efficacy.waf.status) && ['unknown', 'absent', 'present_unmeasured'].includes(efficacy.cdn.status)) ? (
          <p className="td-muted">Not measured. Detection alone does not show whether anything is blocked.</p>
        ) : null}
        {efficacy ? (
          <dl className="td-efficacy-list">
            {([['waf', 'Web application firewall'], ['cdn', 'CDN and edge']] as const).map(([layer, title]) => {
              const value = efficacy[layer];
              return (
                <div key={layer} data-layer={layer}>
                  <dt>{title}</dt>
                  <dd>
                    <Badge tone={value.tone}>{value.label}</Badge>
                    <span className="td-efficacy-sentence">{efficacySentence(value)}</span>
                    {layer === 'waf' && ruleLines.length ? (
                      <ul className="td-rule-lines">
                        {ruleLines.map((line) => (
                          <li key={line.id}>
                            <strong>{line.label}:</strong> <span className="tabular-nums">{line.ratio}</span>
                            <span className="td-muted"> · {line.detail}</span>
                            {line.id === 'custom' && canaryMembers.length ? (
                              <details className="td-canary-members">
                                <summary><ChevronRight size={14} aria-hidden="true" />Custom rules behind this ratio ({canaryMembers.length})</summary>
                                <ul aria-label="Custom canary rules and the run each result came from">
                                  {canaryMembers.map((member) => (
                                    <li key={`${member.checkId}|${member.runId}`}>
                                      <span className="td-canary-name">{checkName?.(member.checkId) || member.checkId}</span>
                                      {member.verdict ? <Badge tone={member.evidence === 'fresh' ? verdictTone(member.verdict) : 'muted'}>{member.evidence === 'fresh' ? plainVerdictShortLabel(member.verdict) : `Stored: ${member.verdict}`}</Badge> : null}
                                      <span className="td-muted">{member.label}{member.observedAt ? ` · ${formatDate(member.observedAt)}` : ''}</span>
                                      {member.runId
                                        ? <a className="detail-entity-link mono" href={buildDetailHref('run-detail', member.runId)} aria-label={`Run ${member.runId} for ${checkName?.(member.checkId) || member.checkId}`}>{member.runId}</a>
                                        : <span className="td-muted">No run recorded</span>}
                                    </li>
                                  ))}
                                </ul>
                              </details>
                            ) : null}
                          </li>
                        ))}
                      </ul>
                    ) : null}
                  </dd>
                </div>
              );
            })}
          </dl>
        ) : null}
        {effectiveness ? (
          <p className="td-muted">
            Fingerprint scan only, not counted above: <span className="tabular-nums">{effectiveness.blocked}</span> markers blocked ·{' '}
            <span className="tabular-nums">{effectiveness.allowed}</span> allowed · <span className="tabular-nums">{effectiveness.inconclusive}</span> inconclusive.
          </p>
        ) : null}
        <details className="td-efficacy-about">
          <summary>How this is decided</summary>
          <p className="td-copy">
            Only results from the coverage freshness window, recorded with the current check version, count. A layer reads <b>Protecting</b> only with at least 3 fresh concluded checks across 2 rule categories and no failure. A DNS zone-transfer refusal never counts toward the CDN, and <b>Bypassable via origin</b> appears only when an origin-lockdown check finds your origin answering directly.
          </p>
          <p className="td-copy">
            <b>Managed rule markers</b> are harmless strings that common managed rule sets (SQL injection, cross-site scripting, path traversal, scanner detection) recognise. <b>Custom canary observations</b> use AstraNull&apos;s own token. Installed rule tokens and placements are not bound to these checks, so they do not verify custom-rule action or attack-class coverage. Only current, verified verdicts count above.
          </p>
        </details>
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
  if (row.status === 'not_tested') return row.missingInput?.message || 'Not tested — this check needs more input, so nothing was sent.';
  if (row.status === 'skipped' || row.status === 'cancelled') return row.reason ? humanizeReason(row.reason) : `${row.label}.`;
  if (row.status === 'retained') return row.coverageReason === 'no_evidence'
    ? 'The stored outcome has no evidence references. It is not a current verified result; rerun this check.'
    : row.coverageReason === 'invalid_or_unresolved_evidence'
      ? 'The stored outcome could not be verified against its evidence. It is not a current gap or pass; rerun this check.'
      : 'This outcome is retained for history, but does not count as a current verified result. Review its evidence or rerun this check.';
  if (row.status === 'observed') return row.explanation || 'Recorded external behavior, with no readiness credit.';
  return row.explanation || (row.verdict ? plainVerdictLabel(row.verdict) : row.label);
}

function checkClassInput(row: CheckRow) {
  return { check_id: row.checkId, vector_family: row.category.id, probe_profile: { kind: row.probeKind } };
}

export function rowImpact(row: CheckRow): CheckImpactId {
  return classifyCheckImpact(checkClassInput(row)).id;
}

function checkActivityMarkers(row: CheckRow): ActivityMarker[] {
  const markers: ActivityMarker[] = [];
  if (row.startedAt) markers.push({ id: `start:${row.runId || row.checkId}`, at: row.startedAt, severity: 'info', label: `Run started: ${row.name}` });
  if (row.finishedAt) {
    const severity = row.status === 'failed' ? 'error' : row.status === 'inconclusive' ? 'warn' : ['passed', 'blocked', 'observed'].includes(row.status) ? 'ok' : 'info';
    markers.push({ id: `outcome:${row.runId || row.checkId}`, at: row.finishedAt, severity, label: `Outcome: ${row.label}`, detail: row.explanation ? humanizeReason(row.explanation) : '' });
  }
  return markers;
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
  liveNote,
  selectedRunItems,
  prerequisite,
  targetId = '',
  omitLayer = false,
  omitControls = [],
  omitImpact = false,
  omitDeclaration = false,
}: {
  row: CheckRow;
  omitLayer?: boolean;
  omitControls?: string[];
  omitImpact?: boolean;
  omitDeclaration?: boolean;
  selected: boolean;
  onSelect: (checkId: string) => void;
  included: boolean;
  canInclude: boolean;
  onToggleInclude?: (checkId: string) => void;
  onInspect: (row: CheckRow) => void;
  onStopCheck?: (row: CheckRow) => void;
  /** Set when the server says this pair's result is retained, not current live external evidence. */
  liveNote?: string;
  selectedRunItems?: DataItem[];
  prerequisite?: CheckPrerequisite;
  targetId?: string;
}) {
  const StatusIcon = STATUS_ICONS[row.status] ?? CircleDashed;
  const blocked = Boolean(prerequisite && prerequisite.state !== 'ready');
  const prerequisiteId = `td-prereq-${row.checkId.replace(/[^a-zA-Z0-9_-]/g, '-')}`;
  const sent = rowSentLine(row);
  const resultType = row.producesVerdict ? row.readinessCapable ? '' : 'Scoped verdict' : 'Observation only';
  const activityItems = selected ? (Array.isArray(selectedRunItems) ? selectedRunItems : []) : [];
  const activityMarkers = selected ? checkActivityMarkers(row) : [];
  const statusLabel = liveNote && ['passed', 'failed'].includes(row.status) ? 'Retained · not current' : row.label;
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
              disabled={!canInclude || (blocked && !included)}
              onChange={() => onToggleInclude(row.checkId)}
              aria-label={`Include ${row.name} in run`}
              aria-describedby={blocked ? prerequisiteId : undefined}
            />
          </label>
        ) : <span className="td-check-choice" aria-hidden="true" />}
        <button type="button" className="td-check-summary" aria-expanded={selected} onClick={() => onSelect(row.checkId)}>
          <span className="td-check-icon" data-tone={row.tone}>
            <StatusIcon size={16} className={row.status === 'running' ? 'td-spin' : undefined} aria-hidden="true" />
          </span>
          <span className="td-check-name">
            <span className="td-check-title"><strong>{row.name}</strong>{resultType ? <span className="td-check-tier">{resultType}</span> : null}</span>
            <span className="td-check-chips">
              <code>{row.checkId}</code>
              {omitImpact ? null : <CheckImpactBadge impact={rowImpact(row)} />}
              <CheckClassChips check={checkClassInput(row)} omitLayer={omitLayer} omitControls={omitControls} omitDeclaration={omitDeclaration} />
            </span>
          </span>
          <span className="td-check-badges">
            <Badge tone={liveNote ? 'muted' : row.tone} title={liveNote ? `Not live evidence: ${liveNote}` : undefined}>{statusLabel}</Badge>
            {blocked && prerequisite ? <Badge tone={prerequisiteTone(prerequisite)} title={prerequisite.detail}>{prerequisite.label}</Badge> : null}
          </span>
          <ChevronRight size={16} className="td-chevron" aria-hidden="true" />
        </button>
      </div>
      {selected ? (
        <div className="td-check-open">
          <dl className="td-check-detail">
            {blocked && prerequisite ? (
              <div className="td-prereq">
                <dt>Before it can run</dt>
                <dd id={prerequisiteId}>
                  {prerequisite.detail}
                  {targetId && prerequisiteSection(prerequisite) ? (
                    <span className="td-prereq-actions">
                      <AnchorButton size="sm" variant="secondary" href={controlsHref(targetId, prerequisiteSection(prerequisite))}>{prerequisiteCta(prerequisite)}</AnchorButton>
                      {prerequisite.missing.slice(1).map((key) => {
                        const meta = DECLARATION_KEYS[key as keyof typeof DECLARATION_KEYS];
                        return meta ? <AnchorButton key={key} size="sm" variant="ghost" href={controlsHref(targetId, meta.section)}>{meta.cta}</AnchorButton> : null;
                      })}
                    </span>
                  ) : null}
                  {prerequisite.state === 'soc_only' ? <span className="td-prereq-actions"><AnchorButton size="sm" variant="secondary" href="#support">Request through SOC</AnchorButton></span> : null}
                </dd>
              </div>
            ) : null}
            <div><dt>Purpose</dt><dd>{row.description || row.category.how}</dd></div>
            {row.mechanism ? <div><dt>How it works</dt><dd>{row.mechanism}</dd></div> : null}
            {row.limitations ? <div><dt>Limits</dt><dd>{row.limitations}</dd></div> : null}
            {row.nextStep ? <div><dt>Next step</dt><dd>{row.nextStep}</dd></div> : null}
            <div><dt>Result type</dt><dd>{row.producesVerdict ? row.readinessCapable ? 'Produces a readiness verdict' : 'Produces a scoped policy verdict; no readiness credit' : 'Observation only; no readiness credit'}{TIER_COPY[row.tier] ? ` · ${TIER_COPY[row.tier]}` : ''}</dd></div>
            {row.expectedBehavior ? <div><dt>Expectation</dt><dd>{humanizeReason(row.expectedBehavior)}</dd></div> : null}
            <div><dt>Upper bound</dt><dd>{rowRequestLine(row)}</dd></div>
            {sent ? <div><dt>Logical operations</dt><dd className="tabular-nums">{sent}{row.requestsSimulated ? '' : ' (attested)'}</dd></div> : null}
            {row.response ? <div><dt>Response</dt><dd>{formatStepResponse(row.response)}</dd></div> : null}
            {row.status === 'not_run' ? null : <div>
              <dt>Result</dt>
              <dd>
                {row.status === 'running' ? (
                  <span className="td-live-result-line">
                    <span className="td-pulse-beacon-inline" aria-hidden="true" />
                    <strong>Awaiting recorded response</strong>
                    <span className="td-muted">{row.requestsSent != null ? ` · ${row.requestsSent} logical operations (attested)` : ' · Logical operation count not recorded yet'}</span>
                  </span>
                ) : row.status === 'not_tested' && row.missingInput ? (
                  <NotTestedNote info={row.missingInput} targetId={blocked ? '' : targetId} showLabel={false} />
                ) : (
                  rowResultLine(row)
                )}
              </dd>
            </div>}
            {liveNote ? <div><dt>Coverage</dt><dd>Saved from an earlier run, not current live evidence: {liveNote}.</dd></div> : null}
            {row.finishedAt || row.startedAt ? <div><dt>{row.finishedAt ? 'Finished' : 'Started'}</dt><dd>{formatDate(row.finishedAt || row.startedAt)}</dd></div> : null}
          </dl>
          {row.runId || row.status === 'running' ? (
            <div className="td-check-terminal-wrapper">
              <UnifiedActivityLog
                items={activityItems}
                markers={activityMarkers}
                active={row.status === 'running'}
                label={row.name}
                requestsSent={row.requestsSent}
                maxRequests={row.maxRequests}
                emptyMessage="No probe activity recorded for this check yet."
              />
            </div>
          ) : null}
          {row.runId || ['blocked', 'skipped', 'cancelled'].includes(row.status) ? (
            <div className="td-check-links">
              {row.runId && row.status === 'running' && onStopCheck ? <Button size="sm" variant="danger" aria-label={`Stop ${row.name}`} onClick={() => onStopCheck(row)}><Square size={13} aria-hidden="true" />Stop this check</Button> : null}
              {row.runId ? (
                <Button size="sm" variant="secondary" data-focus-key={`check-evidence-${row.checkId}`} onClick={() => onInspect(row)}>
                  <Eye size={14} aria-hidden="true" />View evidence
                </Button>
              ) : null}
            </div>
          ) : null}
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
  /** Execution selection remains independent of the complete browsable inventory. */
  runnableCheckIds: ReadonlySet<string>;
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
  footer?: ReactNode;
  liveNotes?: Record<string, string>;
  scanActivity?: DataItem[];
  selectedRunItems?: DataItem[];
  targetValue?: string;
  /** Run-all is unavailable for this target (for example ownership is not proven). */
  runAllDisabledReason?: string;
  /** Run-all is temporarily blocked (for example another check holds the execution slot). */
  runAllBlockedReason?: string;
  recommendedRow?: CheckRow | null;
  onStartRecommended?: (row: CheckRow) => void;
  runSelection?: string[];
  onRunSelectionChange?: (next: string[]) => void;
  /** Port or declaration still missing per check; unmet checks stay out of run-all and multi-select. */
  prerequisites?: Record<string, CheckPrerequisite>;
  targetId?: string;
};

/** Complete check inventory, grouped by category, with separate execution eligibility. */
export function CheckQueue({
  rows,
  runnableCheckIds,
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
  footer,
  liveNotes = {},
  scanActivity = [],
  selectedRunItems = [],
  targetValue = 'target',
  runAllDisabledReason = '',
  runAllBlockedReason = '',
  recommendedRow = null,
  onStartRecommended,
  runSelection = [],
  onRunSelectionChange,
  prerequisites = {},
  targetId = '',
}: CheckQueueProps) {
  const isReady = (checkId: string) => runnableCheckIds.has(checkId) && prerequisites[checkId]?.state === 'ready';
  const readyCount = rows.filter((row) => isReady(row.checkId)).length;
  const waitingCount = rows.length - readyCount;
  const [filter, setFilter] = useState<QueueFilter>('all');
  const [impact, setImpact] = useState<ImpactFilter>('all');
  const [openCategories, setOpenCategories] = useState<Record<string, boolean>>({});
  const selection = useMemo(() => new Set(runSelection), [runSelection]);
  const counts = useMemo(() => {
    const result: Record<string, number> = { all: rows.length, verdict: 0 };
    for (const row of rows) {
      result[row.status] = (result[row.status] ?? 0) + 1;
      if (row.producesVerdict) result.verdict += 1;
    }
    return result;
  }, [rows]);
  const impactCounts = useMemo(() => {
    const result: Record<ImpactFilter, number> = { all: rows.length, non_invasive: 0, invasive: 0 };
    for (const row of rows) result[rowImpact(row)] += 1;
    return result;
  }, [rows]);
  const filtering = filter !== 'all' || impact !== 'all';
  const matchesFilter = (row: CheckRow) => (impact === 'all' || rowImpact(row) === impact)
    && (filter === 'all' || (filter === 'verdict' ? row.producesVerdict : row.status === filter));
  const visibleRows = filtering ? rows.filter((row) => matchesFilter(row) || row.checkId === selectedCheckId) : rows;
  const filteredIds = filtering ? rows.filter(matchesFilter).map((row) => row.checkId).filter(isReady) : [];
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
    const next = new Set(runSelection.filter(isReady));
    for (const id of ids) {
      if (!runnableCheckIds.has(id)) continue;
      if (include && !isReady(id)) continue;
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
  const filterLabel = [
    impact !== 'all' ? CHECK_IMPACT_CLASSES[impact].label : '',
    filter !== 'all' ? FILTERS.find((entry) => entry.id === filter)?.label ?? '' : '',
  ].filter(Boolean).join(' · ');

  return (
    <section className="td-checks" id="td-all-checks" aria-labelledby="td-checks-title">
      <header className="td-section-head">
        <div>
          <h2 id="td-checks-title">Checks for this target</h2>
          <p className="td-checks-stats tabular-nums">
            {catalogCount != null
              ? <><span><strong>{catalogCount}</strong> in the catalog</span><span><strong>{readyCount}</strong> eligible here</span></>
              : <span><strong>{rows.length}</strong> loaded · full catalog not available yet</span>}
            {waitingCount ? <span><strong>{waitingCount}</strong> need setup or cannot run here</span> : null}
          </p>
          <p>Availability is separate from recorded results. Tick eligible checks to review a run; the server re-checks authorization before starting.</p>
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
      {recommendedRow && isReady(recommendedRow.checkId) && onStartRecommended && canRun && !scanActive && !runAllBlockedReason ? (
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
      <div className="td-queue-toolbar">
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
              {entry.id === 'all' && catalogCount == null ? 'Loaded' : entry.label}<span className="tabular-nums">{counts[entry.id] ?? 0}</span>
            </button>
          ))}
          {canInclude && filtering && filteredIds.length ? (
            <Button size="sm" variant="ghost" className="td-filter-select" onClick={() => changeSelection(filteredIds, true)}>
              Select {filterLabel.toLowerCase()} ({filteredIds.length})
            </Button>
          ) : null}
        </div>
        <div className="td-impact" role="group" aria-labelledby="td-impact-title" aria-describedby="td-impact-help">
          <span className="td-label" id="td-impact-title">Traffic impact</span>
          <div className="td-impact-switch">
            {IMPACT_FILTERS.map((entry) => (
              <button
                key={entry.id}
                type="button"
                className="td-impact-option"
                data-impact={entry.id}
                aria-pressed={impact === entry.id}
                onClick={() => setImpact(entry.id)}
              >
                {entry.id !== 'all' ? <CheckImpactIcon impact={entry.id} /> : null}
                {entry.label}<span className="tabular-nums">{impactCounts[entry.id]}</span>
              </button>
            ))}
          </div>
        </div>
      </div>
      <p className="td-muted td-impact-help" id="td-impact-help">
        {impact === 'all'
          ? `${impactCounts.non_invasive} non-invasive checks only observe with ordinary requests. ${impactCounts.invasive} invasive checks send bounded, attack-shaped traffic and can trigger WAF, IDS or SOC alerts, so tell your security team first.`
          : CHECK_IMPACT_CLASSES[impact].summary}
      </p>
      {groups.length ? <CheckClassLegend className="td-check-class-legend" /> : null}
      {groups.map((group) => {
        const Icon = CATEGORY_ICONS[group.category.icon] ?? Shield;
        const classes = group.rows.map((row) => classifyCheck(checkClassInput(row)));
        const impacts = group.rows.map(rowImpact);
        const multiple = group.rows.length > 1;
        const sharedImpact = multiple && impacts.every((value) => value === impacts[0]) ? impacts[0] : null;
        const sharedLayer = multiple && classes[0]?.layer && classes.every((value) => value.layer?.osi === classes[0].layer?.osi && value.layer?.label === classes[0].layer?.label);
        const sharedControls = multiple ? (classes[0]?.controls ?? []).map((control) => control.id).filter((id) => classes.every((value) => value.controls.some((control) => control.id === id))) : [];
        const sharedDeclaration = multiple && classes.every((value) => value.declaration_only);
        const sharedChips = sharedImpact || sharedLayer || sharedControls.length || sharedDeclaration;
        const firstControls = (classes[0]?.controls ?? []).map((control) => control.id);
        const holdsSelection = group.rows.some((row) => row.checkId === selectedCheckId);
        const computedDefault = holdsSelection || filtering || group.counts.failed > 0 || group.counts.running > 0 || rows.length <= 12;
        if (defaultsRef.current[group.category.id] === undefined || holdsSelection) defaultsRef.current[group.category.id] = defaultsRef.current[group.category.id] || computedDefault;
        const defaultOpen = defaultsRef.current[group.category.id];
        const open = openCategories[group.category.id] ?? defaultOpen;
        return (
          <div key={group.category.id} className="td-cat-shell" data-selectable={canInclude || undefined}>
          {canInclude ? (
            <CategorySelect label={group.category.label} ids={group.rows.map((row) => row.checkId).filter(isReady)} selection={selection} disabled={!canInclude} onChange={changeSelection} />
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
                <span className="td-cat-meta">
                  <span className="td-muted">{group.rows.length} check{group.rows.length === 1 ? '' : 's'}</span>
                  {sharedChips ? (
                    <span className="td-check-chips">
                      <span className="sr-only">Shared by every check in this group:</span>
                      {sharedImpact ? <CheckImpactBadge impact={sharedImpact} /> : null}
                      <CheckClassChips
                        check={checkClassInput(group.rows[0])}
                        omitLayer={!sharedLayer}
                        omitControls={firstControls.filter((id) => !sharedControls.includes(id))}
                        omitDeclaration={!sharedDeclaration}
                      />
                    </span>
                  ) : null}
                </span>
              </span>
              <span className="td-cat-tally">
                {group.counts.failed ? <Badge tone="danger">{`${group.counts.failed} gap${group.counts.failed === 1 ? '' : 's'}`}</Badge> : null}
                {group.counts.passed ? <Badge tone="success">{`${group.counts.passed} protected`}</Badge> : null}
                {group.counts.retained ? <Badge tone="muted">{`${group.counts.retained} retained, not current`}</Badge> : null}
                {group.counts.inconclusive ? <Badge tone="muted">{`${group.counts.inconclusive} inconclusive`}</Badge> : null}
                {group.counts.not_tested ? <Badge tone="muted">{`${group.counts.not_tested} not tested`}</Badge> : null}
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
                  canInclude={canInclude && isReady(row.checkId)}
                  onToggleInclude={canInclude ? (checkId) => changeSelection([checkId], !selection.has(checkId)) : undefined}
                  onInspect={onInspect}
                  onStopCheck={onStopCheck}
                  liveNote={liveNotes[row.checkId]}
                  selectedRunItems={row.checkId === selectedCheckId ? selectedRunItems : undefined}
                  prerequisite={prerequisites[row.checkId]}
                  targetId={targetId}
                  omitImpact={Boolean(sharedImpact)}
                  omitLayer={Boolean(sharedLayer)}
                  omitControls={sharedControls}
                  omitDeclaration={sharedDeclaration}
                />
              ))}
            </ul>
          </details>
          </div>
        );
      })}
      {!groups.length ? (
        <p className="td-muted">
          No checks match this filter. <button type="button" className="td-inline-link" onClick={() => { setFilter('all'); setImpact('all'); }}>Show all checks</button>
        </p>
      ) : null}
      {footer}
    </section>
  );
}
