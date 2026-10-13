import * as React from 'react';
import { cva, type VariantProps } from 'class-variance-authority';
import { cn } from '../../lib/utils';
import './primitives.css';

const badgeVariants = cva('badge', {
  variants: {
    tone: {
      default: 'badge-default',
      success: 'badge-success',
      warn: 'badge-warn',
      danger: 'badge-danger',
      info: 'badge-info',
      muted: 'badge-muted'
    }
  },
  defaultVariants: {
    tone: 'default'
  }
});

export type BadgeProps = React.HTMLAttributes<HTMLSpanElement> &
  VariantProps<typeof badgeVariants> & {
    /** Kept for API compatibility; every chip uses the mono uppercase foundation (DESIGN.md). */
    mono?: boolean;
    /**
     * Leading status dot in the tone's ink. Decorative only: the label text still
     * carries the meaning, so tone is never conveyed by color alone.
     */
    dot?: boolean;
  };

export function Badge({ className, tone, mono: _mono, dot = false, children, ...props }: BadgeProps) {
  return (
    <span
      data-ui="badge"
      data-tone={tone ?? 'default'}
      className={cn(badgeVariants({ tone }), className)}
      {...props}
    >
      {dot ? <span className="badge-dot" aria-hidden="true" /> : null}
      {decorateBadgeChildren(children)}
    </span>
  );
}

function decorateBadgeChildren(children: React.ReactNode): React.ReactNode {
  return React.Children.map(children, (child) => {
    if (!React.isValidElement<{ 'aria-hidden'?: boolean; focusable?: boolean }>(child)) return child;
    if (typeof child.type === 'string' && child.type === 'svg') {
      return React.cloneElement(child, { 'aria-hidden': true, focusable: false });
    }
    return child;
  });
}
