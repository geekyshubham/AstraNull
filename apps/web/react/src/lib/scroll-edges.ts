import { useCallback, useEffect, useState } from 'react';

export type ScrollEdgeState = 'none' | 'start' | 'middle' | 'end';

/**
 * Track which horizontal edges of a scroll container still have content behind
 * them.
 *
 * Wide data tables scroll inside their own region, but nothing said so: a
 * column simply ended mid-word at the card edge and looked like truncated data.
 * `none` means everything fits and no affordance should paint at all.
 */
export function useScrollEdges<T extends HTMLElement>() {
  const [node, setNode] = useState<T | null>(null);
  const [edges, setEdges] = useState<ScrollEdgeState>('none');

  const measure = useCallback((element: T) => {
    const overflow = element.scrollWidth - element.clientWidth;
    if (overflow <= 1) {
      setEdges('none');
      return;
    }
    const atStart = element.scrollLeft <= 1;
    const atEnd = element.scrollLeft >= overflow - 1;
    setEdges(atStart ? 'start' : atEnd ? 'end' : 'middle');
  }, []);

  useEffect(() => {
    if (!node) return undefined;
    const onScroll = () => measure(node);
    onScroll();
    node.addEventListener('scroll', onScroll, { passive: true });
    // Column widths change with data, container width, and font loading, so the
    // measurement has to react to layout, not just to scrolling. Measuring on the
    // next frame instead of inside the observer callback keeps the state update
    // out of the same layout pass that delivered the notification.
    let frame = 0;
    const observer = typeof ResizeObserver === 'function'
      ? new ResizeObserver(() => {
        cancelAnimationFrame(frame);
        frame = requestAnimationFrame(onScroll);
      })
      : null;
    observer?.observe(node);
    return () => {
      cancelAnimationFrame(frame);
      node.removeEventListener('scroll', onScroll);
      observer?.disconnect();
    };
  }, [measure, node]);

  return { setScrollNode: setNode, edges };
}
