/**
 * Data results and inline visuals for assistant answers. Numbers come from the server's own query
 * results; the model only chooses where a result appears (`[[data:Q1|bar]]`), never its values.
 */

export const VISUAL_TYPES = Object.freeze(['table', 'bar', 'line', 'donut']);
export const MAX_RESULTS = 8;
export const MAX_COLUMNS = 12;
export const MAX_ROWS = 200;
export const MAX_BAR_CATEGORIES = 20;
export const MAX_DONUT_SLICES = 6;

const COLUMN_TYPES = new Set(['string', 'number', 'date']);
const ID = /^Q\d{1,3}$/;
const MARKER = /\[\[data:(Q\d{1,3})(?:\|([a-z]+))?\]\]/g;
const MARKER_LINE = /^\s*\[\[data:(Q\d{1,3})(?:\|([a-z]+))?\]\]\s*$/;

function text(value, max) {
  if (value === null || value === undefined) return '';
  return String(value).replace(/[\u0000-\u001f\u007f]+/g, ' ').trim().slice(0, max);
}

function cell(value, type) {
  if (value === null || value === undefined || value === '') return null;
  if (type === 'number') {
    const number = typeof value === 'number' ? value : Number(value);
    return Number.isFinite(number) ? number : null;
  }
  if (typeof value === 'number' || typeof value === 'boolean') return String(value);
  return typeof value === 'string' ? text(value, 200) : null;
}

/** Validates one server data result; malformed results are dropped, not repaired. */
export function sanitizeDataResult(value) {
  if (!value || typeof value !== 'object') return null;
  const id = text(value.id, 8);
  if (!ID.test(id)) return null;
  const columns = (Array.isArray(value.columns) ? value.columns : []).slice(0, MAX_COLUMNS).flatMap((column) => {
    const key = text(column?.key, 60);
    if (!key) return [];
    const type = COLUMN_TYPES.has(column?.type) ? column.type : 'string';
    return [{ key, label: text(column?.label, 80) || key, type }];
  });
  if (!columns.length) return null;
  const rows = (Array.isArray(value.rows) ? value.rows : []).slice(0, MAX_ROWS).flatMap((row) => {
    if (!Array.isArray(row)) return [];
    return [columns.map((column, index) => cell(row[index], column.type))];
  });
  const suggested = VISUAL_TYPES.includes(value.suggested_visual) ? value.suggested_visual : 'table';
  return { id, title: text(value.title, 120) || id, columns, rows, suggested_visual: suggested };
}

export function sanitizeDataResults(value) {
  const seen = new Set();
  return (Array.isArray(value) ? value : []).map(sanitizeDataResult).filter((result) => {
    if (!result || seen.has(result.id)) return false;
    seen.add(result.id);
    return true;
  }).slice(0, MAX_RESULTS);
}

export function sanitizeToolCalls(value) {
  return (Array.isArray(value) ? value : []).flatMap((call) => {
    const name = text(call?.name, 60).replace(/[^a-z0-9_.-]/gi, '');
    if (!name) return [];
    return [{ name, summary: text(call?.summary, 200) }];
  }).slice(0, 16);
}

/**
 * Splits an answer into markdown and data segments. A marker line places a known result; an
 * unknown id or visual type is ignored, and inline markers are removed from the text.
 */
export function splitAnswer(content, results) {
  const known = new Set((results ?? []).map((result) => result.id));
  const segments = [];
  let buffer = [];
  const flush = () => {
    const joined = buffer.join('\n').replace(MARKER, '').replace(/\n{3,}/g, '\n\n').trim();
    if (joined) segments.push({ type: 'markdown', text: joined });
    buffer = [];
  };
  for (const line of String(content ?? '').split('\n')) {
    const marker = line.match(MARKER_LINE);
    if (marker) {
      flush();
      if (known.has(marker[1])) segments.push({ type: 'data', id: marker[1], visual: VISUAL_TYPES.includes(marker[2]) ? marker[2] : '' });
      continue;
    }
    buffer.push(line);
  }
  flush();
  return segments;
}

/** Results the answer never placed, listed afterwards so no data the server read is hidden. */
export function unplacedResults(segments, results) {
  const placed = new Set(segments.filter((segment) => segment.type === 'data').map((segment) => segment.id));
  return (results ?? []).filter((result) => !placed.has(result.id));
}

function firstIndex(result, type) {
  return result.columns.findIndex((column) => column.type === type);
}

function labelIndex(result) {
  const string = firstIndex(result, 'string');
  return string >= 0 ? string : firstIndex(result, 'date');
}

function dateMs(value) {
  const ms = Date.parse(String(value ?? ''));
  return Number.isFinite(ms) ? ms : null;
}

/** Bar data: one label and one number per row, largest first. Null when a bar would mislead. */
export function barSeries(result) {
  const label = labelIndex(result);
  const value = firstIndex(result, 'number');
  if (label < 0 || value < 0) return null;
  const series = result.rows
    .filter((row) => typeof row[value] === 'number')
    .map((row) => ({ label: String(row[label] ?? '—'), value: row[value] }))
    .sort((left, right) => right.value - left.value);
  if (!series.length || series.length > MAX_BAR_CATEGORIES) return null;
  return series;
}

/** Line data: a date column and a number column, oldest first. Null without two dated points. */
export function lineSeries(result) {
  const time = firstIndex(result, 'date');
  const value = firstIndex(result, 'number');
  if (time < 0 || value < 0) return null;
  const points = result.rows
    .map((row) => ({ at: dateMs(row[time]), label: String(row[time] ?? ''), value: row[value] }))
    .filter((point) => point.at !== null && typeof point.value === 'number')
    .sort((left, right) => left.at - right.at);
  return points.length >= 2 ? points : null;
}

/** Donut data: non-negative parts of a whole, at most six slices plus "Other". */
export function donutSlices(result) {
  const series = barSeries({ ...result, rows: result.rows });
  if (!series) return null;
  if (series.some((item) => item.value < 0)) return null;
  const total = series.reduce((sum, item) => sum + item.value, 0);
  if (total <= 0) return null;
  const head = series.slice(0, MAX_DONUT_SLICES);
  const rest = series.slice(MAX_DONUT_SLICES).reduce((sum, item) => sum + item.value, 0);
  const slices = rest > 0 ? [...head, { label: 'Other', value: rest }] : head;
  return slices.map((slice) => ({ ...slice, share: slice.value / total }));
}

/** The visual actually drawn: the requested one when the data supports it, else a table. */
export function chooseVisual(result, requested) {
  const wanted = VISUAL_TYPES.includes(requested) && requested ? requested : result.suggested_visual;
  if (wanted === 'bar' && barSeries(result)) return 'bar';
  if (wanted === 'line' && lineSeries(result)) return 'line';
  if (wanted === 'donut' && donutSlices(result)) return 'donut';
  return 'table';
}

function formatNumber(value) {
  return Number.isInteger(value) ? value.toLocaleString('en-US') : value.toLocaleString('en-US', { maximumFractionDigits: 2 });
}

/** One sentence for screen readers that states what the chart shows. */
export function summarizeVisual(result, visual) {
  if (visual === 'bar') {
    const series = barSeries(result) ?? [];
    const top = series.slice(0, 3).map((item) => `${item.label} ${formatNumber(item.value)}`).join(', ');
    return `${result.title}: bar chart of ${series.length} ${series.length === 1 ? 'category' : 'categories'}, largest first: ${top}.`;
  }
  if (visual === 'line') {
    const points = lineSeries(result) ?? [];
    const first = points[0];
    const last = points[points.length - 1];
    return `${result.title}: line chart of ${points.length} points from ${first?.label} (${formatNumber(first?.value ?? 0)}) to ${last?.label} (${formatNumber(last?.value ?? 0)}).`;
  }
  if (visual === 'donut') {
    const slices = donutSlices(result) ?? [];
    return `${result.title}: ${slices.map((slice) => `${slice.label} ${Math.round(slice.share * 100)}%`).join(', ')}.`;
  }
  return `${result.title}: table of ${result.rows.length} ${result.rows.length === 1 ? 'row' : 'rows'}.`;
}

/** Stable sort for table headers; empty cells always sort last. */
export function sortRows(rows, index, direction, type) {
  const sign = direction === 'descending' ? -1 : 1;
  return [...rows].sort((left, right) => {
    const a = left[index];
    const b = right[index];
    if (a === null || a === undefined) return b === null || b === undefined ? 0 : 1;
    if (b === null || b === undefined) return -1;
    if (type === 'number') return (a - b) * sign;
    if (type === 'date') return ((dateMs(a) ?? 0) - (dateMs(b) ?? 0)) * sign;
    return String(a).localeCompare(String(b)) * sign;
  });
}

function csvCell(value) {
  if (value === null || value === undefined) return '';
  let raw = String(value);
  if (/^[=+\-@\t\r]/.test(raw) && typeof value !== 'number') raw = `'${raw}`;
  return /[",\n\r]/.test(raw) ? `"${raw.replace(/"/g, '""')}"` : raw;
}

/** CSV with spreadsheet formula prefixes neutralised. */
export function toCsv(result) {
  const lines = [result.columns.map((column) => csvCell(column.label)).join(',')];
  for (const row of result.rows) lines.push(row.map(csvCell).join(','));
  return lines.join('\n');
}

export function formatCell(value, type) {
  if (value === null || value === undefined || value === '') return '—';
  if (type === 'number' && typeof value === 'number') return formatNumber(value);
  if (type === 'date') {
    const ms = dateMs(value);
    return ms === null ? String(value) : new Date(ms).toISOString().slice(0, 10);
  }
  return String(value);
}
