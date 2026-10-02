import { useCallback, useEffect, useLayoutEffect, useRef, useState } from 'react';

/**
 * Shared motion budget. These mirror the `--motion-*` CSS tokens so JS-driven
 * tweens and CSS transitions cannot drift apart (DESIGN.md "Geometry, spacing,
 * and motion").
 */
/** Press feedback tier (`--motion-micro`): a tap must answer before it is released. */
export const MOTION_MICRO_MS = 90;
export const MOTION_FAST_MS = 120;
export const MOTION_BASE_MS = 200;
export const MOTION_SLOW_MS = 300;
/** Chart/gauge value sweeps only — a measured read, not decoration. */
export const MOTION_MEASURE_MS = 900;

const REDUCED_MOTION_QUERY = '(prefers-reduced-motion: reduce)';

export function prefersReducedMotion(): boolean {
  if (typeof window === 'undefined' || typeof window.matchMedia !== 'function') return true;
  return window.matchMedia(REDUCED_MOTION_QUERY).matches;
}

/**
 * Live `prefers-reduced-motion` state.
 *
 * Defaults to "reduced" until the first layout pass so a JS tween can never
 * start before the preference is known, and re-renders if the user changes the
 * OS setting while the portal is open.
 */
export function useReducedMotion(): boolean {
  const [reduced, setReduced] = useState(true);

  useLayoutEffect(() => {
    if (typeof window === 'undefined' || typeof window.matchMedia !== 'function') return undefined;
    const query = window.matchMedia(REDUCED_MOTION_QUERY);
    setReduced(query.matches);
    function onChange(event: MediaQueryListEvent) {
      setReduced(event.matches);
    }
    query.addEventListener('change', onChange);
    return () => query.removeEventListener('change', onChange);
  }, []);

  return reduced;
}

/**
 * Bring `child` fully into view inside a horizontally scrolling `container`
 * (tab rails, segmented controls) without moving the page vertically.
 *
 * `Element.scrollIntoView` also scrolls every ancestor, which yanks the page
 * when the rail sits below the fold; this only adjusts the rail's own
 * `scrollLeft`. Smooth scrolling is dropped under reduced motion.
 */
export function scrollIntoInlineView(container: HTMLElement | null, child: HTMLElement | null, gutter = 8): void {
  if (!container || !child) return;
  if (container.scrollWidth <= container.clientWidth) return;
  const containerRect = container.getBoundingClientRect();
  const childRect = child.getBoundingClientRect();
  let delta = 0;
  if (childRect.left < containerRect.left + gutter) {
    delta = childRect.left - containerRect.left - gutter;
  } else if (childRect.right > containerRect.right - gutter) {
    delta = childRect.right - containerRect.right + gutter;
  }
  if (delta === 0) return;
  const left = container.scrollLeft + delta;
  if (typeof container.scrollTo === 'function') {
    container.scrollTo({ left, behavior: prefersReducedMotion() ? 'auto' : 'smooth' });
  } else {
    container.scrollLeft = left;
  }
}

function easeOutCubic(t: number): number {
  return 1 - (1 - t) ** 3;
}

type AnimatedNumberOptions = {
  duration?: number;
  /** Opt a specific value out of tweening (e.g. a still-loading metric). */
  enabled?: boolean;
};

/**
 * Tween a numeric metric toward `target` on the animation frame clock.
 *
 * Value changes are a functional signal here: a readiness score moving from 61
 * to 78 should be legible as a change, not a silent repaint. Reduced motion,
 * non-finite input, and a disabled flag all resolve to `target` immediately, so
 * every caller can render the returned value unconditionally.
 */
export function useAnimatedNumber(target: number, options: AnimatedNumberOptions = {}): number {
  const { duration = MOTION_SLOW_MS, enabled = true } = options;
  const reduced = useReducedMotion();
  const settled = Number.isFinite(target) ? target : 0;
  const skip = reduced || !enabled || !Number.isFinite(target);
  const [value, setValue] = useState(settled);
  const fromRef = useRef(settled);
  const frameRef = useRef(0);

  useEffect(() => {
    if (skip) {
      fromRef.current = settled;
      setValue(settled);
      return undefined;
    }
    const from = fromRef.current;
    if (from === settled) return undefined;

    const start = performance.now();
    function step(now: number) {
      const progress = duration <= 0 ? 1 : Math.min(1, (now - start) / duration);
      const next = from + (settled - from) * easeOutCubic(progress);
      fromRef.current = next;
      setValue(next);
      if (progress < 1) {
        frameRef.current = requestAnimationFrame(step);
        return;
      }
      fromRef.current = settled;
      setValue(settled);
    }
    frameRef.current = requestAnimationFrame(step);
    return () => cancelAnimationFrame(frameRef.current);
  }, [duration, settled, skip]);

  return skip ? settled : value;
}

/**
 * One-shot enter animation trigger driven by viewport intersection.
 *
 * Returns `true` (already revealed) whenever motion is unavailable — reduced
 * motion, no `IntersectionObserver`, or a caller that passed `enabled: false` —
 * so content is never left in a hidden pre-animation state.
 */
export function useRevealOnView<T extends HTMLElement>(options: { enabled?: boolean; rootMargin?: string } = {}) {
  const { enabled = true, rootMargin = '0px 0px -12% 0px' } = options;
  const reduced = useReducedMotion();
  const supported = typeof IntersectionObserver === 'function';
  const active = enabled && !reduced && supported;
  const [revealed, setRevealed] = useState(!active);
  const nodeRef = useRef<T | null>(null);

  const setNode = useCallback((node: T | null) => {
    nodeRef.current = node;
  }, []);

  useLayoutEffect(() => {
    if (!active) {
      setRevealed(true);
      return undefined;
    }
    const node = nodeRef.current;
    if (!node) {
      setRevealed(true);
      return undefined;
    }
    const observer = new IntersectionObserver(
      (entries) => {
        if (!entries.some((entry) => entry.isIntersecting)) return;
        setRevealed(true);
        observer.disconnect();
      },
      { rootMargin, threshold: 0.05 }
    );
    observer.observe(node);
    return () => observer.disconnect();
  }, [active, rootMargin]);

  return { setNode, revealed, animating: active };
}

/**
 * Bump a key each time `value` changes, after the first commit.
 *
 * Route and tab surfaces use this to replay a short enter animation on
 * navigation without re-animating on the initial page load, which DESIGN.md
 * rules out as page-load choreography.
 */
export function useTransitionKey(value: string): { key: string; entering: boolean } {
  const firstRef = useRef(true);
  const previousRef = useRef(value);
  const [entering, setEntering] = useState(false);

  useEffect(() => {
    if (firstRef.current) {
      firstRef.current = false;
      previousRef.current = value;
      return;
    }
    if (previousRef.current === value) return;
    previousRef.current = value;
    setEntering(true);
  }, [value]);

  useEffect(() => {
    if (!entering) return undefined;
    const timer = window.setTimeout(() => setEntering(false), MOTION_BASE_MS + MOTION_FAST_MS);
    return () => window.clearTimeout(timer);
  }, [entering, value]);

  return { key: value, entering };
}
