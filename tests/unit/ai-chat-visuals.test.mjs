import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  MAX_ROWS,
  barSeries,
  chooseVisual,
  donutSlices,
  formatCell,
  lineSeries,
  sanitizeDataResult,
  sanitizeDataResults,
  sanitizeToolCalls,
  sortRows,
  splitAnswer,
  summarizeVisual,
  toCsv,
  unplacedResults,
} from '../../apps/web/react/src/lib/assistant-visuals.mjs';

const severity = sanitizeDataResult({
  id: 'Q1',
  title: 'Open findings by severity',
  columns: [{ key: 'severity', label: 'Severity', type: 'string' }, { key: 'count', label: 'Findings', type: 'number' }],
  rows: [['medium', 4], ['critical', 2], ['high', 7], ['low', '1']],
  suggested_visual: 'bar',
});

const trend = sanitizeDataResult({
  id: 'Q2',
  title: 'Runs per day',
  columns: [{ key: 'day', label: 'Day', type: 'date' }, { key: 'runs', label: 'Runs', type: 'number' }],
  rows: [['2026-10-03', 5], ['2026-10-01', 2], ['2026-10-02', 3]],
  suggested_visual: 'line',
});

describe('assistant data results', () => {
  it('validates results and drops malformed ones', () => {
    assert.equal(sanitizeDataResult({ id: 'X1', title: 't', columns: [{ key: 'a' }], rows: [] }), null);
    assert.equal(sanitizeDataResult({ id: 'Q1', title: 't', columns: [], rows: [] }), null);
    assert.deepEqual(severity.rows[3], ['low', 1]);
    const odd = sanitizeDataResult({ id: 'Q9', columns: [{ key: 'n', type: 'number' }, { key: 's', type: 'weird' }], rows: [['abc', { x: 1 }], 'not-a-row'], suggested_visual: 'pie' });
    assert.deepEqual(odd.rows, [[null, null]]);
    assert.equal(odd.columns[1].type, 'string');
    assert.equal(odd.suggested_visual, 'table');
    assert.equal(odd.title, 'Q9');
    const big = sanitizeDataResult({ id: 'Q3', columns: [{ key: 'n', type: 'number' }], rows: Array.from({ length: 500 }, (_, index) => [index]) });
    assert.equal(big.rows.length, MAX_ROWS);
  });

  it('keeps one result per id and cleans tool calls', () => {
    assert.equal(sanitizeDataResults([severity, severity, trend, null]).length, 2);
    assert.deepEqual(sanitizeToolCalls([{ name: 'query_findings<script>', summary: 'Open findings by severity' }, { name: '' }]), [{ name: 'query_findingsscript', summary: 'Open findings by severity' }]);
  });
});

describe('assistant answer markers', () => {
  it('places known results on marker lines and ignores unknown ids', () => {
    const content = 'Here is the split.\n[[data:Q1|bar]]\nAnd the trend:\n[[data:Q2]]\n[[data:Q7|bar]]\nDone.';
    const segments = splitAnswer(content, [severity, trend]);
    assert.deepEqual(segments, [
      { type: 'markdown', text: 'Here is the split.' },
      { type: 'data', id: 'Q1', visual: 'bar' },
      { type: 'markdown', text: 'And the trend:' },
      { type: 'data', id: 'Q2', visual: '' },
      { type: 'markdown', text: 'Done.' },
    ]);
  });

  it('strips inline markers and ignores unknown visual types', () => {
    const segments = splitAnswer('See [[data:Q1]] below.\n[[data:Q1|radar]]', [severity]);
    assert.deepEqual(segments, [{ type: 'markdown', text: 'See  below.' }, { type: 'data', id: 'Q1', visual: '' }]);
  });

  it('lists results the answer never placed', () => {
    const segments = splitAnswer('Only one.\n[[data:Q1]]', [severity, trend]);
    assert.deepEqual(unplacedResults(segments, [severity, trend]).map((result) => result.id), ['Q2']);
    assert.deepEqual(splitAnswer('', undefined), []);
  });
});

describe('assistant chart helpers', () => {
  it('sorts bars largest first and refuses too many categories', () => {
    assert.deepEqual(barSeries(severity).map((item) => item.label), ['high', 'medium', 'critical', 'low']);
    const wide = { ...severity, rows: Array.from({ length: 21 }, (_, index) => [`c${index}`, index]) };
    assert.equal(barSeries(wide), null);
    assert.equal(chooseVisual(wide, 'bar'), 'table');
  });

  it('orders line points by date and needs two of them', () => {
    assert.deepEqual(lineSeries(trend).map((point) => point.value), [2, 3, 5]);
    assert.equal(lineSeries({ ...trend, rows: [['2026-10-01', 1]] }), null);
    assert.equal(chooseVisual(severity, 'line'), 'table');
    assert.equal(chooseVisual(trend, undefined), 'line');
  });

  it('builds donut slices with an Other slice and refuses negatives', () => {
    const parts = { ...severity, rows: [['a', 10], ['b', 9], ['c', 8], ['d', 7], ['e', 6], ['f', 5], ['g', 3], ['h', 2]] };
    const slices = donutSlices(parts);
    assert.equal(slices.length, 7);
    assert.deepEqual(slices[6], { label: 'Other', value: 5, share: 5 / 50 });
    assert.equal(Math.round(slices.reduce((sum, slice) => sum + slice.share, 0) * 1000) / 1000, 1);
    assert.equal(donutSlices({ ...severity, rows: [['a', 3], ['b', -1]] }), null);
    assert.equal(donutSlices({ ...severity, rows: [['a', 0]] }), null);
    assert.equal(chooseVisual(severity, 'donut'), 'donut');
  });

  it('summarises charts for screen readers', () => {
    assert.match(summarizeVisual(severity, 'bar'), /^Open findings by severity: bar chart of 4 categories, largest first: high 7, medium 4, critical 2\.$/);
    assert.match(summarizeVisual(trend, 'line'), /3 points from 2026-10-01 \(2\) to 2026-10-03 \(5\)/);
    assert.match(summarizeVisual(severity, 'donut'), /high 50%/);
    assert.equal(summarizeVisual(severity, 'table'), 'Open findings by severity: table of 4 rows.');
  });

  it('sorts table rows with empty cells last', () => {
    const rows = [['a', 2], ['b', null], ['c', 9]];
    assert.deepEqual(sortRows(rows, 1, 'descending', 'number').map((row) => row[0]), ['c', 'a', 'b']);
    assert.deepEqual(sortRows(rows, 1, 'ascending', 'number').map((row) => row[0]), ['a', 'c', 'b']);
    assert.deepEqual(sortRows(trend.rows, 0, 'ascending', 'date').map((row) => row[1]), [2, 3, 5]);
  });

  it('writes CSV that spreadsheets cannot execute', () => {
    const risky = sanitizeDataResult({ id: 'Q4', title: 'x', columns: [{ key: 'name', label: 'Name, full' }, { key: 'n', label: 'N', type: 'number' }], rows: [['=HYPERLINK("x")', -3], ['@cmd', 1], ['plain "quoted"', null]] });
    assert.equal(toCsv(risky), '"Name, full",N\n"\'=HYPERLINK(""x"")",-3\n\'@cmd,1\n"plain ""quoted""",');
  });

  it('formats cells for display', () => {
    assert.equal(formatCell(null, 'string'), '—');
    assert.equal(formatCell(12345, 'number'), '12,345');
    assert.equal(formatCell(1.23456, 'number'), '1.23');
    assert.equal(formatCell('2026-10-02T10:00:00Z', 'date'), '2026-10-02');
  });
});
