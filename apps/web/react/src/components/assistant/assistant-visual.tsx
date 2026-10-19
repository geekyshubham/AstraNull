import { useId, useMemo, useState } from 'react';
import { BarChart3, Check, Copy, Table2 } from 'lucide-react';
import {
  barSeries,
  chooseVisual,
  donutSlices,
  formatCell,
  lineSeries,
  sortRows,
  summarizeVisual,
  toCsv,
  type DataResult,
  type VisualType,
} from '../../lib/assistant-visuals.mjs';

const PAGE = 20;

function DataTable({ result }: { result: DataResult }) {
  const [sort, setSort] = useState<{ index: number; direction: 'ascending' | 'descending' } | null>(null);
  const [shown, setShown] = useState(PAGE);
  const rows = useMemo(
    () => (sort ? sortRows(result.rows, sort.index, sort.direction, result.columns[sort.index].type) : result.rows),
    [result, sort],
  );
  function toggle(index: number) {
    setSort((current) => (current?.index === index
      ? { index, direction: current.direction === 'ascending' ? 'descending' : 'ascending' }
      : { index, direction: result.columns[index].type === 'string' ? 'ascending' : 'descending' }));
  }
  if (!rows.length) return <p className="as-vis-empty">No rows matched.</p>;
  return (
    <>
      <div className="as-vis-table" role="region" tabIndex={0} aria-label={`${result.title} table`}>
        <table>
          <thead>
            <tr>
              {result.columns.map((column, index) => (
                <th key={column.key} scope="col" aria-sort={sort?.index === index ? sort.direction : 'none'} data-type={column.type}>
                  <button type="button" onClick={() => toggle(index)}>
                    {column.label}
                    <span className="as-sort-mark" aria-hidden="true">{sort?.index === index ? (sort.direction === 'ascending' ? '↑' : '↓') : '↕'}</span>
                  </button>
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {rows.slice(0, shown).map((row, rowIndex) => (
              <tr key={rowIndex}>
                {row.map((value, index) => (
                  <td key={result.columns[index].key} data-type={result.columns[index].type}>{formatCell(value, result.columns[index].type)}</td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {rows.length > shown ? (
        <button type="button" className="as-vis-more" onClick={() => setShown((value) => value + PAGE * 5)}>
          Show more ({rows.length - shown} more {rows.length - shown === 1 ? 'row' : 'rows'})
        </button>
      ) : null}
    </>
  );
}

function BarChart({ result, summary }: { result: DataResult; summary: string }) {
  const series = barSeries(result) ?? [];
  const max = Math.max(...series.map((item) => item.value), 0) || 1;
  const valueLabel = result.columns.find((column) => column.type === 'number')?.label ?? 'Value';
  return (
    <figure className="as-bars" role="img" aria-label={summary}>
      <ol>
        {series.map((item) => (
          <li key={item.label}>
            <span className="as-bar-label" title={item.label}>{item.label}</span>
            <span className="as-bar-track" aria-hidden="true">
              <span className="as-bar-fill" style={{ inlineSize: `${Math.max(2, (item.value / max) * 100)}%` }} />
            </span>
            <span className="as-bar-value tabular-nums">{formatCell(item.value, 'number')}</span>
          </li>
        ))}
      </ol>
      <figcaption className="sr-only">{valueLabel}</figcaption>
    </figure>
  );
}

const W = 320;
const H = 150;
const PAD = { top: 12, right: 12, bottom: 26, left: 36 };

function LineChart({ result, summary }: { result: DataResult; summary: string }) {
  const points = lineSeries(result) ?? [];
  const min = Math.min(0, ...points.map((point) => point.value));
  const max = Math.max(...points.map((point) => point.value), min + 1);
  const t0 = points[0]?.at ?? 0;
  const t1 = points[points.length - 1]?.at ?? 1;
  const x = (at: number) => PAD.left + ((at - t0) / Math.max(1, t1 - t0)) * (W - PAD.left - PAD.right);
  const y = (value: number) => PAD.top + (1 - (value - min) / (max - min)) * (H - PAD.top - PAD.bottom);
  const path = points.map((point, index) => `${index ? 'L' : 'M'}${x(point.at).toFixed(1)},${y(point.value).toFixed(1)}`).join(' ');
  const ticks = [min, (min + max) / 2, max];
  const day = (at: number) => new Date(at).toISOString().slice(5, 10);
  return (
    <svg className="as-line" viewBox={`0 0 ${W} ${H}`} role="img" aria-label={summary} preserveAspectRatio="xMidYMid meet">
      {ticks.map((tick) => (
        <g key={tick} className="as-line-grid">
          <line x1={PAD.left} x2={W - PAD.right} y1={y(tick)} y2={y(tick)} />
          <text x={PAD.left - 6} y={y(tick)} dy="0.32em" textAnchor="end">{formatCell(Math.round(tick * 10) / 10, 'number')}</text>
        </g>
      ))}
      <path className="as-line-path" d={path} />
      {points.map((point) => <circle key={point.at} className="as-line-point" cx={x(point.at)} cy={y(point.value)} r={3}><title>{`${point.label}: ${formatCell(point.value, 'number')}`}</title></circle>)}
      <text className="as-line-axis" x={PAD.left} y={H - 8} textAnchor="start">{day(t0)}</text>
      <text className="as-line-axis" x={W - PAD.right} y={H - 8} textAnchor="end">{day(t1)}</text>
    </svg>
  );
}

function DonutChart({ result, summary }: { result: DataResult; summary: string }) {
  const slices = donutSlices(result) ?? [];
  const radius = 36;
  const circumference = 2 * Math.PI * radius;
  let offset = 0;
  return (
    <div className="as-donut">
      <svg viewBox="0 0 100 100" role="img" aria-label={summary}>
        <circle className="as-donut-base" cx="50" cy="50" r={radius} />
        {slices.map((slice, index) => {
          const length = slice.share * circumference;
          const node = (
            <circle
              key={slice.label}
              className="as-donut-slice"
              data-slice={index}
              cx="50"
              cy="50"
              r={radius}
              strokeDasharray={`${Math.max(0, length - 1.2)} ${circumference}`}
              strokeDashoffset={-offset}
              transform="rotate(-90 50 50)"
            />
          );
          offset += length;
          return node;
        })}
      </svg>
      <ul className="as-donut-legend">
        {slices.map((slice, index) => (
          <li key={slice.label}>
            <span className="as-donut-swatch" data-slice={index} aria-hidden="true" />
            <span className="as-donut-label" title={slice.label}>{slice.label}</span>
            <span className="as-donut-value tabular-nums">{formatCell(slice.value, 'number')}</span>
            <span className="as-donut-share tabular-nums">{Math.round(slice.share * 100)}%</span>
          </li>
        ))}
      </ul>
    </div>
  );
}

function CopyCsv({ result }: { result: DataResult }) {
  const [copied, setCopied] = useState(false);
  async function copy() {
    try {
      await navigator.clipboard.writeText(toCsv(result));
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1600);
    } catch {
      setCopied(false);
    }
  }
  return (
    <button type="button" className="as-vis-btn" onClick={() => void copy()} aria-label={copied ? `${result.title} copied as CSV` : `Copy ${result.title} as CSV`}>
      {copied ? <Check size={13} aria-hidden="true" /> : <Copy size={13} aria-hidden="true" />}
      <span>{copied ? 'Copied' : 'Copy CSV'}</span>
    </button>
  );
}

/** One data result: the chart the answer asked for when the data supports it, with a table view. */
export function AssistantVisual({ result, requested }: { result: DataResult; requested?: VisualType | '' }) {
  const visual = chooseVisual(result, requested || undefined);
  const [view, setView] = useState<'chart' | 'table'>(visual === 'table' ? 'table' : 'chart');
  const titleId = useId();
  const summary = summarizeVisual(result, visual);
  const showChart = visual !== 'table' && view === 'chart';
  return (
    <section className="as-vis" aria-labelledby={titleId} data-visual={visual}>
      <header className="as-vis-head">
        <h4 id={titleId}>{result.title}</h4>
        <span className="as-vis-actions">
          {visual !== 'table' ? (
            <span className="as-vis-toggle" role="group" aria-label={`${result.title} view`}>
              <button type="button" className="as-vis-btn" aria-pressed={view === 'chart'} onClick={() => setView('chart')}>
                <BarChart3 size={13} aria-hidden="true" /><span>Chart</span>
              </button>
              <button type="button" className="as-vis-btn" aria-pressed={view === 'table'} onClick={() => setView('table')}>
                <Table2 size={13} aria-hidden="true" /><span>Table</span>
              </button>
            </span>
          ) : null}
          <CopyCsv result={result} />
        </span>
      </header>
      {showChart && visual === 'bar' ? <BarChart result={result} summary={summary} /> : null}
      {showChart && visual === 'line' ? <LineChart result={result} summary={summary} /> : null}
      {showChart && visual === 'donut' ? <DonutChart result={result} summary={summary} /> : null}
      {showChart ? null : <DataTable result={result} />}
      <p className="as-vis-note">{result.rows.length} {result.rows.length === 1 ? 'row' : 'rows'} from your workspace data</p>
    </section>
  );
}
