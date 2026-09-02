import * as React from 'react';
import { MOTION_MEASURE_MS, useAnimatedNumber, useRevealOnView, useTransitionKey } from '../../lib/motion';
import { cn, formatNumber } from '../../lib/utils';

export type AnimatedNumberProps = Omit<React.HTMLAttributes<HTMLSpanElement>, 'children'> & {
  value: number;
  /** Render the in-flight and settled value; defaults to a grouped integer. */
  format?: (value: number) => string;
  duration?: number;
  animate?: boolean;
};

/**
 * A metric that counts toward its value instead of snapping.
 *
 * The settled string is always identical to what a plain render would produce,
 * so assertions, copy/paste, and screen readers see the real number. The tween
 * is skipped entirely under reduced motion.
 */
export function AnimatedNumber({
  value,
  format,
  duration,
  animate = true,
  className,
  ...props
}: AnimatedNumberProps) {
  const animated = useAnimatedNumber(value, { duration, enabled: animate });
  const render = format ?? ((next: number) => formatNumber(Math.round(next)));
  const settled = Math.round(animated) === Math.round(value);

  return (
    <span
      data-ui="animated-number"
      data-settled={settled ? 'true' : 'false'}
      className={cn('animated-number', className)}
      {...props}
    >
      {render(animated)}
    </span>
  );
}

export type RevealProps = React.HTMLAttributes<HTMLElement> & {
  /** Stagger position within a group; each step adds one micro-interval. */
  step?: number;
  as?: 'div' | 'section' | 'li';
  enabled?: boolean;
};

/**
 * Enter-on-first-view wrapper for narrative marketing sections.
 *
 * Deliberately not used inside the operator console, where an operator scanning
 * a dense table should never wait on a reveal. Content renders visible whenever
 * motion is unavailable, so nothing can be trapped in a pre-animation state.
 */
export function Reveal({ step = 0, as = 'div', enabled = true, className, children, ...props }: RevealProps) {
  const { setNode, revealed, animating } = useRevealOnView<HTMLElement>({ enabled });
  const Component = as as React.ElementType;

  return (
    <Component
      ref={setNode}
      className={cn('reveal', animating && 'reveal-armed', revealed && 'is-revealed', className)}
      style={step > 0 ? ({ '--reveal-step': String(step) } as React.CSSProperties) : undefined}
      {...props}
    >
      {children}
    </Component>
  );
}

export type RouteTransitionProps = {
  /** Changing this replays the enter animation; equal values do not. */
  routeKey: string;
  className?: string;
  children: React.ReactNode;
};

/**
 * Short cross-fade-and-rise on navigation.
 *
 * Keyed on the route so the first paint of a page load stays still, and each
 * subsequent route change reads as a deliberate move rather than a hard cut.
 */
export function RouteTransition({ routeKey, className, children }: RouteTransitionProps) {
  const { key, entering } = useTransitionKey(routeKey);

  return (
    <div key={key} className={cn('route-transition', entering && 'is-entering', className)}>
      {children}
    </div>
  );
}

export type AnimatedArcOptions = {
  /** 0–100. */
  percent: number;
  radius: number;
  animate?: boolean;
};

/**
 * Stroke-dashoffset sweep for a circular gauge.
 *
 * Uses the measure-tier duration: a readiness arc sweeping to its value is the
 * chart's read of the number, not decoration.
 */
export function useAnimatedArc({ percent, radius, animate = true }: AnimatedArcOptions) {
  const swept = useAnimatedNumber(percent, { duration: MOTION_MEASURE_MS, enabled: animate });
  const dash = 2 * Math.PI * radius;
  return { dash, offset: dash - (dash * swept) / 100, value: swept };
}
