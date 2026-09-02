import type { DataItem } from '../../lib/types';
import { cn, scoreTone } from '../../lib/utils';
import { Badge } from '../ui/badge';

type ScoreTrendProps = {
  runs: DataItem[];
  currentScore: number;
  tone?: 'success' | 'warn' | 'danger';
};

type ScoreTone = NonNullable<ScoreTrendProps['tone']>;
type VerdictTone = ScoreTone | 'muted';

const TONE_STROKE: Record<ScoreTone, string> = {
  success: 'var(--success)',
  warn: 'var(--warn)',
  danger: 'var(--danger)',
};

const TERMINAL_VERDICT_STATUSES = new Set(['completed', 'verdicted', 'finalized']);

function asDataItem(value: unknown): DataItem | null {
  return value && typeof value === 'object' && !Array.isArray(value) ? (value as DataItem) : null;
}

function readinessScoreValue(value: unknown): number | null {
  return typeof value === 'number' && Number.isFinite(value) && value >= 0 && value <= 100
    ? value
    : null;
}

function nonNegativeNumberValue(value: unknown): number | null {
  return typeof value === 'number' && Number.isFinite(value) && value >= 0 ? value : null;
}

/** Returns only readiness-specific score fields supplied by the run API. */
function runReadinessScore(run: DataItem): number | null {
  const summary = asDataItem(run.summary);
  const readiness = asDataItem(run.readiness);
  const result = asDataItem(run.result);
  const candidates = [
    run.readiness_score,
    run.readinessScore,
    summary?.readiness_score,
    summary?.readinessScore,
    readiness?.score,
    result?.readiness_score,
    result?.readinessScore,
  ];

  for (const candidate of candidates) {
    const score = readinessScoreValue(candidate);
    if (score !== null) return score;
  }
  return null;
}

function evidenceReferences(item: DataItem | null): unknown[] {
  return item && Array.isArray(item.evidence_ids) ? item.evidence_ids : [];
}

/**
 * Returns a published verdict only when the run is terminal or carries an
 * evidence reference. Run lifecycle status is never substituted for a verdict.
 */
function evidenceBackedRunVerdict(run: DataItem): string | null {
  const nested = asDataItem(run.verdict);
  const direct = typeof run.verdict === 'string' ? run.verdict : null;
  const nestedValue = nested?.verdict ?? nested?.result ?? nested?.status;
  const verdict = direct ?? (typeof nestedValue === 'string' ? nestedValue : null);
  if (!verdict) return null;

  const key = verdict.trim().toLowerCase();
  if (!key || ['pending', 'planned', 'running', 'collecting'].includes(key)) return null;

  const status = typeof run.status === 'string' ? run.status.trim().toLowerCase() : '';
  const evidenceCount = nonNegativeNumberValue(run.evidence_count);
  const hasEvidenceReference =
    evidenceReferences(run).length > 0 ||
    evidenceReferences(nested).length > 0 ||
    (typeof run.evidence_id === 'string' && run.evidence_id.length > 0) ||
    (evidenceCount !== null && evidenceCount > 0);

  return TERMINAL_VERDICT_STATUSES.has(status) || hasEvidenceReference ? verdict : null;
}

function verdictTone(verdict: string): VerdictTone {
  const key = verdict.trim().toLowerCase();
  if (['pass', 'passed', 'protected', 'allowed_as_expected', 'success', 'ok'].includes(key)) {
    return 'success';
  }
  if (['gap', 'fail', 'failed', 'danger', 'penetrated', 'bypassable', 'edge_exposed', 'unprotected'].includes(key)) {
    return 'danger';
  }
  if (['review', 'warn', 'warning', 'info', 'unknown', 'underprotected', 'edge_protected', 'inconclusive', 'misplaced_agent'].includes(key)) {
    return 'warn';
  }
  return 'muted';
}

function formatVerdict(verdict: string): string {
  const words = verdict.trim().replace(/[_-]+/g, ' ');
  return words ? `${words.charAt(0).toUpperCase()}${words.slice(1)}` : 'Unknown';
}

function runSortKey(run: DataItem): string {
  return String(run.completed_at ?? run.created_at ?? run.started_at ?? run.id ?? '');
}

function runLabel(run: DataItem, index: number): string {
  const id = String(run.id ?? '');
  return id ? `…${id.slice(-8)}` : `Run ${index + 1}`;
}

const TREND_WIDTH = 320;
const TREND_HEIGHT = 120;
const TREND_PAD_LEFT = 28;
const TREND_PAD_RIGHT = 12;
const TREND_PAD_Y = 12;

function trendCoordinates(values: number[]) {
  const plotWidth = TREND_WIDTH - TREND_PAD_LEFT - TREND_PAD_RIGHT;
  const plotHeight = TREND_HEIGHT - TREND_PAD_Y * 2;
  return values.map((value, index) => {
    const x = values.length === 1
      ? TREND_PAD_LEFT + plotWidth / 2
      : TREND_PAD_LEFT + (index * plotWidth) / (values.length - 1);
    const y = TREND_HEIGHT - TREND_PAD_Y - (value / 100) * plotHeight;
    return { x, y };
  });
}

export function ScoreTrend({ runs, currentScore, tone }: ScoreTrendProps) {
  const sortedRuns = [...runs].sort((left, right) => runSortKey(left).localeCompare(runSortKey(right)));
  const scoredRuns = sortedRuns
    .map((run) => ({ run, value: runReadinessScore(run) }))
    .filter((entry): entry is { run: DataItem; value: number } => entry.value !== null);
  const verdictRuns = sortedRuns
    .map((run, index) => ({ run, verdict: evidenceBackedRunVerdict(run), index }))
    .filter((entry): entry is { run: DataItem; verdict: string; index: number } => entry.verdict !== null);
  const categoricalOnlyCount = verdictRuns.filter(({ run }) => runReadinessScore(run) === null).length;
  const publishedCurrentScore = readinessScoreValue(currentScore);

  if (scoredRuns.length === 0 && verdictRuns.length === 0) {
    const currentLabel = publishedCurrentScore === null
      ? ''
      : ` Current published score: ${publishedCurrentScore}/100; no per-run score history was returned.`;
    return (
      <div
        className="score-trend score-trend--empty"
        role="status"
        aria-label={`Readiness trend unavailable; no per-run scores or evidence-backed verdicts yet.${currentLabel}`}
      >
        <span className="muted score-trend-caption">
          No per-run readiness scores or evidence-backed verdicts yet.{currentLabel}
        </span>
      </div>
    );
  }

  if (scoredRuns.length === 0) {
    return (
      <div
        className="score-trend"
        role="region"
        aria-label={`Categorical verdict history across ${verdictRuns.length} evidence-backed run${verdictRuns.length === 1 ? '' : 's'}; no per-run readiness scores were returned.`}
      >
        <div className="score-trend-header">
          <span className="score-trend-title">Published verdict history</span>
          <span className="score-trend-subtitle muted">
            No per-run readiness scores returned · showing evidence-backed categories
          </span>
        </div>
        <div className="row wrap">
          {verdictRuns.map(({ run, verdict, index }) => {
            const label = runLabel(run, index);
            return (
              <Badge
                key={`${String(run.id ?? label)}-${index}`}
                tone={verdictTone(verdict)}
                title={`Run ${String(run.id ?? index + 1)} · ${verdict}`}
              >
                {label} · {formatVerdict(verdict)}
              </Badge>
            );
          })}
        </div>
        <span className="muted score-trend-caption">
          {verdictRuns.length} evidence-backed verdict{verdictRuns.length === 1 ? '' : 's'}
          {publishedCurrentScore === null ? '' : ` · current published score ${publishedCurrentScore}/100`}
        </span>
      </div>
    );
  }

  const chartValues = scoredRuns.map(({ value }) => value);
  const coords = trendCoordinates(chartValues);
  const polylinePoints = coords.map(({ x, y }) => `${x},${y}`).join(' ');
  const baselineY = TREND_HEIGHT - TREND_PAD_Y;
  const areaPoints = `${coords[0].x},${baselineY} ${polylinePoints} ${coords[coords.length - 1].x},${baselineY}`;
  const gridLevels = [0, 50, 100];
  const plotHeight = TREND_HEIGHT - TREND_PAD_Y * 2;
  const gridYs = gridLevels.map(
    (level) => TREND_HEIGHT - TREND_PAD_Y - (level / 100) * plotHeight
  );
  const latestScore = publishedCurrentScore ?? scoredRuns[scoredRuns.length - 1].value;
  const strokeTone = tone ?? scoreTone(latestScore);
  const strokeColor = TONE_STROKE[strokeTone];
  const scoreSummary = scoredRuns.map(({ value }) => value).join(', ');
  const ariaLabel = `Readiness score trend across ${scoredRuns.length} run${scoredRuns.length === 1 ? '' : 's'} with published per-run scores: ${scoreSummary}. Current published score: ${latestScore}.`;

  return (
    <div className={cn('score-trend', `score-trend-stroke--${strokeTone}`)} role="img" aria-label={ariaLabel}>
      <div className="score-trend-header">
        <span className="score-trend-title">Run readiness scores</span>
        <span className="score-trend-subtitle muted">Each point is a published per-run readiness score</span>
      </div>
      <svg className="score-trend-svg" viewBox={`0 0 ${TREND_WIDTH} ${TREND_HEIGHT}`} width="100%" preserveAspectRatio="xMidYMid meet" aria-hidden="true">
        {gridYs.map((gy, index) => (
          <g key={gridLevels[index]}>
            <line className="score-trend-grid" x1={TREND_PAD_LEFT} x2={TREND_WIDTH - TREND_PAD_RIGHT} y1={gy} y2={gy} />
            <text className="score-trend-axis-label" x={TREND_PAD_LEFT - 6} y={gy + 3} textAnchor="end">
              {gridLevels[index]}
            </text>
          </g>
        ))}
        <polygon className="score-trend-area" points={areaPoints} />
        <polyline
          className="score-trend-line"
          points={polylinePoints}
          fill="none"
          stroke={strokeColor}
          strokeWidth={2}
          vectorEffect="non-scaling-stroke"
        />
        {coords.map(({ x, y }, index) => {
          const run = scoredRuns[index].run;
          const label = runLabel(run, index);
          return (
            <g key={`${String(run.id ?? label)}-${index}`}>
              <circle className="score-trend-point" cx={x} cy={y} r={4} fill={strokeColor} />
              <title>{`Run ${String(run.id ?? index + 1)} · readiness score ${scoredRuns[index].value}/100`}</title>
            </g>
          );
        })}
      </svg>
      <span className="muted score-trend-caption">
        {scoredRuns.length} scored run{scoredRuns.length === 1 ? '' : 's'}
        {categoricalOnlyCount === 0 ? '' : ` · ${categoricalOnlyCount} categorical-only verdict${categoricalOnlyCount === 1 ? '' : 's'} omitted from the score line`}
        {' · '}current published score {latestScore}/100
      </span>
    </div>
  );
}
