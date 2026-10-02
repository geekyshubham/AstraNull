/**
 * Selection helpers for the readiness score trend chart.
 *
 * The chart remembers which run is active by a stable selection id rather than
 * by array position. The active index is derived synchronously from the current
 * points on every render, so a refresh that removes or replaces runs can never
 * leave the chart indexing past the end of its data.
 *
 * Kept free of runtime imports so node:test can load it directly.
 */

export type SelectablePoint = {
  key: string;
  runId: string;
};

/** Stable identity for a plotted run: its run id, or its render key when the run has no id. */
export function trendSelectionId(point: SelectablePoint): string {
  return point.runId || point.key;
}

/**
 * Resolves the active point index for a remembered selection id.
 * Returns null when nothing is selected or the selected run is no longer plotted.
 */
export function resolveActiveIndex(points: readonly SelectablePoint[], selectedId: string | null): number | null {
  if (selectedId === null || points.length === 0) return null;
  const index = points.findIndex((point) => trendSelectionId(point) === selectedId);
  return index >= 0 && index < points.length ? index : null;
}

/** Returns the selection id at an index, or null when the index is outside the current points. */
export function selectionIdAt(points: readonly SelectablePoint[], index: number | null): string | null {
  if (index === null || !Number.isInteger(index) || index < 0 || index >= points.length) return null;
  return trendSelectionId(points[index]);
}

/**
 * Maps a chart keyboard key to the next active index, bounded to the current points.
 * Returns undefined for keys the chart does not handle, and null to clear the selection.
 */
export function nextKeyboardIndex(key: string, activeIndex: number | null, count: number): number | null | undefined {
  if (key === 'Escape') return null;
  if (count <= 0) return undefined;
  const last = count - 1;
  const current = activeIndex === null ? last : Math.min(Math.max(activeIndex, 0), last);
  if (key === 'ArrowLeft') return Math.max(0, current - 1);
  if (key === 'ArrowRight') return Math.min(last, current + 1);
  if (key === 'Home') return 0;
  if (key === 'End') return last;
  return undefined;
}
