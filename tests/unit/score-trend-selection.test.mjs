import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { describe, it } from 'node:test';
import {
  nextKeyboardIndex,
  resolveActiveIndex,
  selectionIdAt,
  trendSelectionId,
} from '../../apps/web/react/src/components/charts/score-trend-selection.ts';

// Mirrors how ScoreTrend builds plotted points: key is `${id}-${index}`, runId is the run id.
function pointsFor(ids) {
  return ids.map((id, index) => ({ key: `${id || 'run'}-${index}`, runId: id }));
}

/**
 * Simulates the chart's render-time lookup the way TrendLineChart does it:
 * the remembered selection id is resolved against the current points, and the
 * active point is read only through the resolved index.
 */
function renderLookup(points, selectedId) {
  const active = resolveActiveIndex(points, selectedId);
  const activePoint = active === null ? null : points[active] ?? null;
  return { active, activePoint };
}

describe('score trend selection (F01 regression)', () => {
  it('drops the selection when five scored runs shrink to two and the last run was selected', () => {
    const five = pointsFor(['run_a', 'run_b', 'run_c', 'run_d', 'run_e']);
    // Focus the chart, then press End: the latest run becomes active.
    const end = nextKeyboardIndex('End', null, five.length);
    assert.equal(end, 4);
    const selectedId = selectionIdAt(five, end);
    assert.equal(selectedId, 'run_e');

    // Refresh returns only two scored runs; the old numeric index 4 would be out of range.
    const two = pointsFor(['run_a', 'run_b']);
    const { active, activePoint } = renderLookup(two, selectedId);
    assert.equal(active, null);
    assert.equal(activePoint, null);
  });

  it('keeps following the selected run by id when earlier runs are removed', () => {
    const five = pointsFor(['run_a', 'run_b', 'run_c', 'run_d', 'run_e']);
    const selectedId = selectionIdAt(five, 3);
    const two = pointsFor(['run_c', 'run_d']);
    const { active, activePoint } = renderLookup(two, selectedId);
    assert.equal(active, 1);
    assert.equal(activePoint.runId, 'run_d');
  });

  it('does not attach the selection to a different run that replaced the selected one', () => {
    const before = pointsFor(['run_a', 'run_b', 'run_c']);
    const selectedId = selectionIdAt(before, 2);
    const after = pointsFor(['run_a', 'run_b', 'run_z']);
    assert.equal(resolveActiveIndex(after, selectedId), null);
  });

  it('stays bounded when history transitions to one scored run and to none', () => {
    const five = pointsFor(['run_a', 'run_b', 'run_c', 'run_d', 'run_e']);
    const selectedId = selectionIdAt(five, 4);

    const one = pointsFor(['run_a']);
    assert.equal(resolveActiveIndex(one, selectedId), null);
    assert.equal(resolveActiveIndex(one, 'run_a'), 0);

    assert.equal(resolveActiveIndex([], selectedId), null);
    assert.equal(resolveActiveIndex([], null), null);
  });

  it('falls back to the render key for runs without an id', () => {
    const points = pointsFor(['', '']);
    assert.equal(trendSelectionId(points[1]), 'run-1');
    assert.equal(resolveActiveIndex(points, selectionIdAt(points, 1)), 1);
    // Shrinking id-less history cannot resolve past the end either.
    assert.equal(resolveActiveIndex(pointsFor(['']), 'run-1'), null);
  });

  it('rejects out-of-range and non-integer indexes when capturing a selection', () => {
    const points = pointsFor(['run_a', 'run_b']);
    assert.equal(selectionIdAt(points, null), null);
    assert.equal(selectionIdAt(points, -1), null);
    assert.equal(selectionIdAt(points, 2), null);
    assert.equal(selectionIdAt(points, 0.5), null);
    assert.equal(selectionIdAt([], 0), null);
  });

  it('bounds keyboard navigation to the current point count', () => {
    assert.equal(nextKeyboardIndex('ArrowLeft', null, 5), 3);
    assert.equal(nextKeyboardIndex('ArrowRight', null, 5), 4);
    assert.equal(nextKeyboardIndex('ArrowLeft', 0, 5), 0);
    assert.equal(nextKeyboardIndex('Home', 3, 5), 0);
    assert.equal(nextKeyboardIndex('End', 0, 2), 1);
    // A stale index larger than the data is clamped before moving.
    assert.equal(nextKeyboardIndex('ArrowRight', 4, 2), 1);
    assert.equal(nextKeyboardIndex('ArrowLeft', 4, 2), 0);
    assert.equal(nextKeyboardIndex('Escape', 2, 5), null);
    assert.equal(nextKeyboardIndex('Escape', 2, 0), null);
    assert.equal(nextKeyboardIndex('ArrowRight', null, 0), undefined);
    assert.equal(nextKeyboardIndex('Tab', 1, 5), undefined);
  });
});

describe('score trend component wiring (F01 regression)', () => {
  const source = readFileSync('apps/web/react/src/components/charts/score-trend.tsx', 'utf8');

  it('stores the selection by run id instead of a numeric index', () => {
    assert.match(source, /useState<string \| null>\(null\)/);
    assert.match(source, /resolveActiveIndex\(points, selectedId\)/);
    assert.doesNotMatch(source, /useState<number \| null>\(null\)/);
  });

  it('guards every active-point lookup and the live-region description', () => {
    assert.doesNotMatch(source, /const point = points\[index\];\s*return/);
    assert.match(source, /if \(!point\) return '';/);
    assert.match(source, /points\[active\] \?\? null/);
    assert.match(source, /coords\[active\] \?\? null/);
    assert.match(source, /aria-live="polite">\{pointDescription\(active\)\}/);
  });
});
