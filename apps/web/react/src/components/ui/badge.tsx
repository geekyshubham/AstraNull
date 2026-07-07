import * as React from 'react';
import { cva, type VariantProps } from 'class-variance-authority';
import { cn } from '../../lib/utils';

const BADGE_STYLES_ID = 'ui-badge-primitive-styles';

const badgePrimitiveStyles = `
[data-ui='badge'].badge-default,
[data-ui='badge'].badge-muted {
  background: color-mix(in oklab, var(--fg), transparent 96%);
  color: var(--muted);
}
[data-ui='badge'].badge svg {
  color: currentColor;
}
@media (prefers-reduced-motion: reduce) {
  [data-ui='badge'].badge {
    transition: none;
  }
}
`;

function ensureBadgeStyles() {
  if (typeof document === 'undefined') return;
  if (document.getElementById(BADGE_STYLES_ID)) return;
  const node = document.createElement('style');
  node.id = BADGE_STYLES_ID;
  node.textContent = badgePrimitiveStyles;
  document.head.appendChild(node);
}

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
    /**
     * When true, uses mono typography (ID-style chips). Default false uses sans label styling.
     * Optional leading icons: pass as children; prefer Lucide at size 12 with default stroke.
     */
    mono?: boolean;
  };

export function Badge({ className, tone, mono = false, children, ...props }: BadgeProps) {
  ensureBadgeStyles();

  return (
    <span data-ui="badge" className={cn(badgeVariants({ tone }), !mono && 'badge-sans', className)} {...props}>
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