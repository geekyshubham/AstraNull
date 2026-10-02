import {
  useEffect,
  useId,
  useRef,
  useState,
  type KeyboardEvent as ReactKeyboardEvent,
  type PointerEvent as ReactPointerEvent
} from 'react';
import type { DataItem } from '../../lib/types';
import { scoreTone } from '../../lib/utils';
import './score-trend.css';
// @ts-ignore Plain ESM keeps executive labels directly testable with node:test.
import { plainVerdictLabel } from '../../lib/plain-language.mjs';
import { nextKeyboardIndex, resolveActiveIndex, selectionIdAt } from './score-trend-selection';

type ScoreTone = 'success' | 'warn' | 'danger';
type VerdictTone = ScoreTone | 'muted';

type ScoreTrendProps = {
  runs: DataItem[];
  /** Published tenant readiness score from GET /v1/state, or null when none is published. */
  currentScore: number | null;
  tone?: ScoreTone;
};

type ScoredPoint = {
  key: string;
  runId: string;
  label: string;
  value: number;
  date: string;
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

function runTimestamp(run: DataItem): string {
  return String(run.completed_at ?? run.created_at ?? run.started_at ?? '');
}

function runSortKey(run: DataItem): string {
  return runTimestamp(run) || String(run.id ?? '');
}

function runLabel(run: DataItem, index: number): string {
  const id = String(run.id ?? '');
  return id ? `…${id.slice(-8)}` : `Run ${index + 1}`;
}

function shortDate(iso: string): string {
  const ts = Date.parse(iso);
  if (!Number.isFinite(ts)) return '';
  return new Date(ts).toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
}

function plural(count: number, singular: string, pluralForm = `${singular}s`) {
  return count === 1 ? singular : pluralForm;
}

function signedPoints(delta: number) {
  if (delta === 0) return 'No change';
  return `${delta > 0 ? '+' : ''}${delta} ${plural(Math.abs(delta), 'point')}`;
}

/* ---------- Summary figures (shared by every non-empty state) ---------- */

function TrendFigures({
  currentScore,
  points,
  categoricalOnlyCount
}: {
  currentScore: number | null;
  points: ScoredPoint[];
  categoricalOnlyCount: number;
}) {
  const first = points[0];
  const last = points[points.length - 1];
  const delta = points.length >= 2 ? Math.round((last.value - first.value) * 10) / 10 : null;
  return (
    <dl className="trend-figures">
      <div className="trend-figure">
        <dt>Published score</dt>
        <dd>
          {currentScore === null ? 'Not published' : currentScore}
          {currentScore === null ? null : <span className="unit">/100</span>}
        </dd>
      </div>
      <div className="trend-figure">
        <dt>Change across scored runs</dt>
        <dd data-direction={delta === null ? 'none' : delta > 0 ? 'up' : delta < 0 ? 'down' : 'flat'}>
          {delta === null ? 'Needs two runs' : signedPoints(delta)}
        </dd>
      </div>
      <div className="trend-figure">
        <dt>Scored runs</dt>
        <dd>
          {points.length}
          {categoricalOnlyCount > 0 ? (
            <span className="trend-figure-note">{`+${categoricalOnlyCount} verdict-only`}</span>
          ) : null}
        </dd>
      </div>
    </dl>
  );
}

/* ---------- Measured-width hook so axis text never stretches ---------- */

function useMeasuredWidth<T extends HTMLElement>() {
  const ref = useRef<T | null>(null);
  const [width, setWidth] = useState(0);
  useEffect(() => {
    const node = ref.current;
    if (!node) return undefined;
    const update = () => setWidth(Math.floor(node.getBoundingClientRect().width));
    update();
    if (typeof ResizeObserver === 'undefined') return undefined;
    const observer = new ResizeObserver(update);
    observer.observe(node);
    return () => observer.disconnect();
  }, []);
  return [ref, width] as const;
}

/* ---------- Line chart (two or more scored runs) ---------- */

const CHART_HEIGHT = 224;
const PAD_TOP = 18;
const PAD_RIGHT = 16;
const PAD_BOTTOM = 30;
const PAD_LEFT = 36;
const Y_TICKS = [0, 25, 50, 75, 100];
/** Matches the success boundary used by scoreTone and the executive readiness message. */
const READY_THRESHOLD = 80;
const TIP_WIDTH = 148;
/** Above this many scored runs, individual markers crowd the line; only the latest and active run get one. */
const DENSE_POINT_LIMIT = 40;
/** The verdict strip shows at most this many recent runs; the tally still counts every run. */
const VERDICT_STRIP_LIMIT = 60;
const TIP_HEIGHT = 42;

function xTickIndexes(count: number, width: number): number[] {
  if (width < 420) return count > 1 ? [0, count - 1] : [0];
  if (count <= 6) return Array.from({ length: count }, (_unused, index) => index);
  const picks = Array.from({ length: 5 }, (_unused, step) => Math.round((step * (count - 1)) / 4));
  return [...new Set(picks)];
}

function TrendLineChart({
  points,
  currentScore,
  tone,
  categoricalOnlyCount
}: {
  points: ScoredPoint[];
  currentScore: number | null;
  tone: ScoreTone;
  categoricalOnlyCount: number;
}) {
  const [plotRef, width] = useMeasuredWidth<HTMLDivElement>();
  // Selection is remembered by stable run id; the index is re-derived from the
  // current points on every render so shrinking or replaced history cannot
  // leave a stale index pointing past the data (F01).
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const active = resolveActiveIndex(points, selectedId);
  const setActive = (index: number | null) => setSelectedId(selectionIdAt(points, index));
  const tableId = useId();
  const captionId = useId();
  const dense = points.length > DENSE_POINT_LIMIT;

  const count = points.length;
  const plotWidth = Math.max(1, width - PAD_LEFT - PAD_RIGHT);
  const plotHeight = CHART_HEIGHT - PAD_TOP - PAD_BOTTOM;
  const baseline = PAD_TOP + plotHeight;
  const xAt = (index: number) => PAD_LEFT + (count === 1 ? plotWidth / 2 : (index * plotWidth) / (count - 1));
  const yAt = (value: number) => PAD_TOP + (1 - value / 100) * plotHeight;
  const coords = points.map((point, index) => ({ x: xAt(index), y: yAt(point.value) }));
  const linePath = coords.map(({ x, y }, index) => `${index === 0 ? 'M' : 'L'}${x.toFixed(1)} ${y.toFixed(1)}`).join(' ');
  const areaPath = `${linePath} L${coords[count - 1].x.toFixed(1)} ${baseline} L${coords[0].x.toFixed(1)} ${baseline} Z`;

  const first = points[0];
  const last = points[count - 1];
  const low = points.reduce((min, point) => (point.value < min.value ? point : min), first);
  const high = points.reduce((max, point) => (point.value > max.value ? point : max), first);
  const delta = Math.round((last.value - first.value) * 10) / 10;
  const direction = delta > 0 ? `up ${signedPoints(delta).slice(1)}` : delta < 0 ? `down ${signedPoints(delta).slice(1)}` : 'unchanged';
  const summary = `Latest scored run is ${last.value} of 100, ${direction} from the first of ${count} scored runs. Range ${low.value} to ${high.value}.`;
  const ariaLabel = `Readiness score line chart. ${summary} Use the left and right arrow keys to read each run.`;

  function pointDescription(index: number | null) {
    const point = index === null ? undefined : points[index];
    if (!point) return '';
    return `Run ${point.runId || point.label}${point.date ? `, ${point.date}` : ''}: readiness ${point.value} of 100.`;
  }

  function onPointerMove(event: ReactPointerEvent<SVGSVGElement>) {
    const rect = event.currentTarget.getBoundingClientRect();
    const px = event.clientX - rect.left;
    let nearest = 0;
    let best = Number.POSITIVE_INFINITY;
    coords.forEach(({ x }, index) => {
      const distance = Math.abs(x - px);
      if (distance < best) {
        best = distance;
        nearest = index;
      }
    });
    setActive(nearest);
  }

  function onKeyDown(event: ReactKeyboardEvent<HTMLDivElement>) {
    const next = nextKeyboardIndex(event.key, active, count);
    if (next === undefined) return;
    if (next !== null) event.preventDefault();
    setActive(next);
  }

  const activePoint = active === null ? null : points[active] ?? null;
  const activeCoord = active === null ? null : coords[active] ?? null;
  const tipX = activeCoord ? Math.min(Math.max(activeCoord.x - TIP_WIDTH / 2, PAD_LEFT), Math.max(PAD_LEFT, width - PAD_RIGHT - TIP_WIDTH)) : 0;
  const tipY = activeCoord ? (activeCoord.y - TIP_HEIGHT - 12 < 0 ? activeCoord.y + 12 : activeCoord.y - TIP_HEIGHT - 12) : 0;
  const thresholdY = yAt(READY_THRESHOLD);

  return (
    <div className="trend" data-tone={tone}>
      <TrendFigures currentScore={currentScore} points={points} categoricalOnlyCount={categoricalOnlyCount} />
      <div
        ref={plotRef}
        className="trend-plot"
        tabIndex={0}
        role="group"
        aria-roledescription="line chart"
        aria-label={ariaLabel}
        aria-describedby={captionId}
        data-active-run={activePoint ? activePoint.runId || activePoint.label : undefined}
        onKeyDown={onKeyDown}
        onFocus={() => {
          if (active === null) setActive(count - 1);
        }}
        onBlur={() => setActive(null)}
      >
        {width > 0 ? (
          <svg
            width={width}
            height={CHART_HEIGHT}
            viewBox={`0 0 ${width} ${CHART_HEIGHT}`}
            aria-hidden="true"
            focusable="false"
            onPointerMove={onPointerMove}
            onPointerLeave={() => setActive(null)}
          >
            {Y_TICKS.map((tick) => (
              <g key={tick}>
                <line
                  className="trend-grid-line"
                  data-base={tick === 0 ? 'true' : undefined}
                  x1={PAD_LEFT}
                  x2={width - PAD_RIGHT}
                  y1={yAt(tick)}
                  y2={yAt(tick)}
                />
                <text className="trend-axis" x={PAD_LEFT - 8} y={yAt(tick) + 4} textAnchor="end">{tick}</text>
              </g>
            ))}
            <line className="trend-threshold" x1={PAD_LEFT} x2={width - PAD_RIGHT} y1={thresholdY} y2={thresholdY} />
            <text className="trend-threshold-label" x={width - PAD_RIGHT} y={thresholdY - 6} textAnchor="end">
              {`Ready threshold ${READY_THRESHOLD}`}
            </text>
            <path className="trend-area" d={areaPath} />
            <path className="trend-line" d={linePath} />
            {activeCoord ? <line className="trend-guide" x1={activeCoord.x} x2={activeCoord.x} y1={PAD_TOP} y2={baseline} /> : null}
            {coords.map(({ x, y }, index) => (dense && index !== active && index !== count - 1 ? null : (
              <circle
                key={points[index].key}
                className="trend-point"
                data-active={active === index ? 'true' : undefined}
                cx={x}
                cy={y}
                r={active === index ? 5.5 : 3.5}
              />
            )))}
            {xTickIndexes(count, width).map((index) => (
              <text
                key={`x-${points[index].key}`}
                className="trend-axis"
                x={coords[index].x}
                y={CHART_HEIGHT - 8}
                textAnchor={index === 0 ? 'start' : index === count - 1 ? 'end' : 'middle'}
              >
                {points[index].date || points[index].label}
              </text>
            ))}
            {activePoint && activeCoord ? (
              <g className="trend-tip" transform={`translate(${tipX.toFixed(1)} ${tipY.toFixed(1)})`}>
                <rect className="trend-tip-box" width={TIP_WIDTH} height={TIP_HEIGHT} rx={6} />
                <text className="trend-tip-value" x={10} y={17}>{`${activePoint.value} / 100`}</text>
                <text className="trend-tip-meta" x={10} y={33}>
                  {activePoint.date ? `${activePoint.date}, run ${activePoint.label}` : `Run ${activePoint.label}`}
                </text>
              </g>
            ) : null}
          </svg>
        ) : null}
      </div>
      <p className="trend-caption" id={captionId}>
        {summary}
        {categoricalOnlyCount > 0
          ? ` ${categoricalOnlyCount} verdict-only ${plural(categoricalOnlyCount, 'run')} carried no readiness score and ${categoricalOnlyCount === 1 ? 'is' : 'are'} not plotted.`
          : ''}
      </p>
      <p className="sr-only trend-live" aria-live="polite">{pointDescription(active)}</p>
      <table className="sr-only" id={tableId}>
        <caption>Published readiness score per run, oldest first</caption>
        <thead>
          <tr>
            <th scope="col">Run</th>
            <th scope="col">Date</th>
            <th scope="col">Readiness score</th>
          </tr>
        </thead>
        <tbody>
          {points.map((point) => (
            <tr key={point.key}>
              <td>{point.runId || point.label}</td>
              <td>{point.date || 'Not recorded'}</td>
              <td>{point.value}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

/* ---------- One scored run: state the fact, draw no line ---------- */

function SingleScoredRun({
  point,
  currentScore,
  tone,
  categoricalOnlyCount
}: {
  point: ScoredPoint;
  currentScore: number | null;
  tone: ScoreTone;
  categoricalOnlyCount: number;
}) {
  return (
    <div className="trend" data-tone={tone}>
      <TrendFigures currentScore={currentScore} points={[point]} categoricalOnlyCount={categoricalOnlyCount} />
      <div className="trend-pending">
        <p className="trend-pending-title">One scored run so far</p>
        <p>
          {`Run ${point.label}${point.date ? ` on ${point.date}` : ''} published a readiness score of ${point.value} of 100. `}
          A trend line needs at least two scored runs, so none is drawn yet.
        </p>
      </div>
    </div>
  );
}

/* ---------- No per-run scores: evidence-backed verdict sequence ---------- */

const VERDICT_GROUP_LABEL: Record<VerdictTone, string> = {
  success: 'Passed',
  warn: 'Needs review',
  danger: 'Gap found',
  muted: 'Other result'
};

function VerdictHistory({
  verdictRuns,
  currentScore
}: {
  verdictRuns: { run: DataItem; verdict: string; index: number }[];
  currentScore: number | null;
}) {
  const tally: Record<VerdictTone, number> = { success: 0, warn: 0, danger: 0, muted: 0 };
  for (const { verdict } of verdictRuns) tally[verdictTone(verdict)] += 1;
  const groups = (Object.keys(tally) as VerdictTone[]).filter((tone) => tally[tone] > 0);
  const shown = verdictRuns.slice(-VERDICT_STRIP_LIMIT);
  const truncated = verdictRuns.length > shown.length;

  return (
    <div className="trend">
      <TrendFigures currentScore={currentScore} points={[]} categoricalOnlyCount={verdictRuns.length} />
      <div className="verdict-history">
        <p className="trend-pending-title">
          {truncated
            ? `Latest ${shown.length} of ${verdictRuns.length} evidence-backed verdicts, oldest first`
            : 'Evidence-backed verdicts, oldest first'}
        </p>
        <ol className="verdict-strip" aria-label={`Verdicts for ${shown.length} evidence-backed ${plural(shown.length, 'run')}, oldest first`}>
          {shown.map(({ run, verdict, index }) => {
            const label = `Run ${String(run.id ?? index + 1)}: ${plainVerdictLabel(verdict)}`;
            return (
              <li key={`${String(run.id ?? index)}-${index}`} data-tone={verdictTone(verdict)} title={label}>
                <span className="sr-only">{label}</span>
              </li>
            );
          })}
        </ol>
        <ul className="verdict-tally" aria-label={`Verdict tally across all ${verdictRuns.length} evidence-backed ${plural(verdictRuns.length, 'run')}`}>
          {groups.map((tone) => (
            <li key={tone} data-tone={tone}>
              <span className="verdict-tally-swatch" aria-hidden="true" />
              {VERDICT_GROUP_LABEL[tone]}
              <strong>{tally[tone]}</strong>
            </li>
          ))}
        </ul>
      </div>
      <p className="trend-caption">
        These runs carried no readiness score, so no score line is drawn. Each mark is one run with a published, evidence-backed verdict.
      </p>
    </div>
  );
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
    return (
      <div className="trend-empty" role="status">
        <p className="trend-pending-title">No run history to plot yet</p>
        <p>
          No validation run has published a readiness score or an evidence-backed verdict.
          {publishedCurrentScore === null ? '' : ` The current published score is ${publishedCurrentScore} of 100.`}
        </p>
      </div>
    );
  }

  if (scoredRuns.length === 0) {
    return <VerdictHistory verdictRuns={verdictRuns} currentScore={publishedCurrentScore} />;
  }

  const points: ScoredPoint[] = scoredRuns.map(({ run, value }, index) => ({
    key: `${String(run.id ?? 'run')}-${index}`,
    runId: String(run.id ?? ''),
    label: runLabel(run, index),
    value,
    date: shortDate(runTimestamp(run))
  }));
  const latestScore = publishedCurrentScore ?? points[points.length - 1].value;
  const strokeTone = tone ?? (scoreTone(latestScore) as ScoreTone);

  if (points.length === 1) {
    return (
      <SingleScoredRun
        point={points[0]}
        currentScore={publishedCurrentScore}
        tone={strokeTone}
        categoricalOnlyCount={categoricalOnlyCount}
      />
    );
  }

  return (
    <TrendLineChart
      points={points}
      currentScore={publishedCurrentScore}
      tone={strokeTone}
      categoricalOnlyCount={categoricalOnlyCount}
    />
  );
}
